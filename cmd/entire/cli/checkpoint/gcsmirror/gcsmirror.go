// Package gcsmirror implements a non-git-backed checkpoint mirror backend
// ("gcs") that fans out checkpoint writes to a Google Cloud Storage bucket.
//
// It exists for privacy-conscious teams that want checkpoints shared across
// developers without routing them through Entire's own hosted service: the
// git-refs (or git-branch) backend stays the primary — serving all reads, and
// the normal local-first lifecycle (resume, doctor, push) — while this backend
// receives a best-effort copy of every write for the team to read out of a
// bucket they themselves control. It is registered as a MIRROR ONLY (see
// checkpoint.Register / registeredBackend.gitBacked in the parent package):
// its Read*/List* methods are never called by the fan-out store, which reads
// exclusively from the primary.
//
// Objects are optionally encrypted client-side with AES-256-GCM before upload,
// so the bucket (and anyone with read access to it, including Google) only
// ever sees ciphertext. This is a prototype: a real rollout would want a KMS-
// or Secret-Manager-backed key instead of a bare environment variable, and a
// per-write-type retention/compaction policy instead of one object per write.
package gcsmirror

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"golang.org/x/oauth2/google"

	apicheckpoint "github.com/entireio/cli/api/checkpoint"
	"github.com/entireio/cli/cmd/entire/cli/checkpoint"
	"github.com/entireio/cli/cmd/entire/cli/checkpoint/id"
)

// BackendType is the name this backend registers under. Select it as a mirror
// via the checkpoints.mirrors settings block:
//
//	{
//	  "checkpoints": {
//	    "primary": { "type": "git-refs" },
//	    "mirrors": [
//	      { "type": "gcs", "config": { "bucket": "my-team-checkpoints", "prefix": "entire", "encryption_key_env": "ENTIRE_GCS_MIRROR_KEY" } }
//	    ]
//	  }
//	}
const BackendType = "gcs"

// Register installs this backend into the checkpoint registry. The CLI's main
// package must import this package (blank import is fine) before any call to
// checkpoint.Open for the "gcs" mirror type to be selectable; omitting the
// import leaves "gcs" unknown, matching how every other non-built-in backend
// stays out of a binary that never imports it.
func Register() {
	checkpoint.Register(BackendType, factory)
}

// Config is the backend-specific "config" block for the "gcs" mirror.
type Config struct {
	// Bucket is the GCS bucket name (no gs:// prefix).
	Bucket string `json:"bucket"`

	// Prefix is an optional object-name prefix, so one bucket can host several
	// repos' or teams' checkpoints without colliding. Defaults to "entire".
	Prefix string `json:"prefix,omitempty"`

	// EncryptionKeyEnv names an environment variable holding a base64-encoded
	// 32-byte AES-256 key. When set, every uploaded object is encrypted with
	// it before upload (AES-256-GCM, random nonce prefixed to the ciphertext).
	// When empty, objects are uploaded as plaintext JSON/bytes — only do that
	// for a bucket you otherwise trust, e.g. one already restricted to the
	// team and encrypted at rest by GCS itself.
	EncryptionKeyEnv string `json:"encryption_key_env,omitempty"`
}

func factory(ctx context.Context, _ checkpoint.OpenEnv, raw json.RawMessage) (checkpoint.PersistentStore, error) {
	var cfg Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("gcs checkpoint mirror: invalid config: %w", err)
		}
	}
	if cfg.Bucket == "" {
		return nil, errors.New("gcs checkpoint mirror: config.bucket is required")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "entire"
	}

	var aead cipher.AEAD
	if cfg.EncryptionKeyEnv != "" {
		var err error
		aead, err = aeadFromEnv(cfg.EncryptionKeyEnv)
		if err != nil {
			return nil, fmt.Errorf("gcs checkpoint mirror: %w", err)
		}
	}

	// Plain net/http with Application Default Credentials: the mirror only
	// ever uploads whole objects, so the full cloud.google.com/go/storage SDK
	// (and its grpc/otel/protobuf tree) is not needed.
	client, err := google.DefaultClient(ctx, storageScope)
	if err != nil {
		return nil, fmt.Errorf("gcs checkpoint mirror: application default credentials: %w", err)
	}
	client.Timeout = uploadTimeout

	return &store{
		client:  client,
		baseURL: defaultBaseURL,
		bucket:  cfg.Bucket,
		prefix:  cfg.Prefix,
		aead:    aead,
	}, nil
}

// aeadFromEnv reads a base64-encoded 32-byte key from the named environment
// variable and builds an AES-256-GCM AEAD from it.
func aeadFromEnv(envVar string) (cipher.AEAD, error) {
	encoded := os.Getenv(envVar)
	if encoded == "" {
		return nil, fmt.Errorf("encryption key env var %q is not set", envVar)
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("encryption key env var %q is not valid base64: %w", envVar, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key env var %q must decode to 32 bytes (AES-256), got %d", envVar, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build AES-GCM AEAD: %w", err)
	}
	return gcm, nil
}

// store is the "gcs" checkpoint mirror. It satisfies checkpoint.PersistentStore
// so it can be constructed through the same registry as any other backend, but
// only Write is ever exercised in practice: the fan-out store that wires
// mirrors (checkpoint.newFanoutStore) never routes reads to one. The Read*/
// List* methods below return clear errors rather than silently fabricating
// empty results, so a bug that did call them would fail loudly instead of
// looking like "checkpoint not found".
type store struct {
	// client is an authenticated HTTP client (ADC in production, a plain
	// client against httptest in unit tests).
	client *http.Client
	// baseURL is the GCS JSON API origin; overridable for tests.
	baseURL string
	bucket  string
	prefix  string
	// aead encrypts every object this store writes when non-nil. nil means
	// objects are uploaded as plaintext.
	aead cipher.AEAD
}

var _ checkpoint.PersistentStore = (*store)(nil)

var errMirrorOnly = errors.New("gcs checkpoint mirror: reads are not supported; this backend is mirror-only")

func (s *store) Read(context.Context, id.CheckpointID) (*apicheckpoint.CheckpointSummary, error) {
	return nil, errMirrorOnly
}

func (s *store) List(context.Context) ([]apicheckpoint.CheckpointInfo, error) {
	return nil, errMirrorOnly
}

func (s *store) ReadSessionContent(context.Context, id.CheckpointID, int) (*apicheckpoint.SessionContent, error) {
	return nil, errMirrorOnly
}

func (s *store) ReadSessionMetadata(context.Context, id.CheckpointID, int) (*apicheckpoint.Metadata, error) {
	return nil, errMirrorOnly
}

func (s *store) ReadSessionPrompts(context.Context, id.CheckpointID, int) (string, error) {
	return "", errMirrorOnly
}

func (s *store) ReadSessionMetadataAndPrompts(context.Context, id.CheckpointID, int) (*apicheckpoint.Metadata, string, error) {
	return nil, "", errMirrorOnly
}

func (s *store) ListTasks(context.Context, id.CheckpointID) ([]apicheckpoint.TaskEntry, error) {
	return nil, errMirrorOnly
}

func (s *store) ReadTaskTranscript(context.Context, id.CheckpointID, string) ([]byte, error) {
	return nil, errMirrorOnly
}

// Write dispatches on the WriteRequest union, mirroring refs_store.go's
// pattern. Each case uploads one or two objects (a metadata/summary JSON
// document, and for the write kinds that carry one, a separate transcript
// object) under objectPrefix(checkpointID)/.
func (s *store) Write(ctx context.Context, req apicheckpoint.WriteRequest) error {
	switch r := req.(type) {
	case apicheckpoint.Session:
		return s.writeSession(ctx, apicheckpoint.WriteOptions(r))
	case apicheckpoint.ReservedSession:
		return s.writeSession(ctx, apicheckpoint.WriteOptions(r))
	case apicheckpoint.SessionTranscript:
		return s.writeTranscriptUpdate(ctx, apicheckpoint.UpdateOptions(r))
	case apicheckpoint.SessionSummary:
		return s.writeSummary(ctx, r.CheckpointID, r.Summary)
	case apicheckpoint.Tasks:
		return s.writeTasks(ctx, r)
	default:
		return fmt.Errorf("gcs checkpoint mirror: unsupported write request %T", req)
	}
}

// objectPrefix is the common "directory" every object for a checkpoint lives
// under, sharded the same way the git-refs backend shards ref names
// (id.ShardFor), so a bucket browser fans out the same way the git ref
// namespace does instead of putting millions of objects in one flat prefix.
func (s *store) objectPrefix(checkpointID id.CheckpointID) string {
	return path.Join(s.prefix, "checkpoints", checkpointID.ShardFor(), checkpointID.String())
}

// sessionDoc is the JSON document uploaded for a Session/ReservedSession
// write. It mirrors the subset of WriteOptions that matters to a reader
// browsing the bucket directly (e.g. `gsutil cat` or a small viewer script);
// it does not attempt to reproduce the git stores' exact on-disk tree layout,
// which is specific to being spliced into a git tree.
type sessionDoc struct {
	CheckpointID     id.CheckpointID        `json:"checkpoint_id"`
	SessionID        string                 `json:"session_id"`
	CreatedAt        time.Time              `json:"created_at"`
	Strategy         string                 `json:"strategy,omitempty"`
	Branch           string                 `json:"branch,omitempty"`
	CommitSHA        string                 `json:"commit_sha,omitempty"`
	Prompts          []string               `json:"prompts,omitempty"`
	FilesTouched     []string               `json:"files_touched,omitempty"`
	CheckpointsCount int                    `json:"checkpoints_count,omitempty"`
	AuthorName       string                 `json:"author_name,omitempty"`
	AuthorEmail      string                 `json:"author_email,omitempty"`
	Agent            string                 `json:"agent,omitempty"`
	Model            string                 `json:"model,omitempty"`
	Kind             string                 `json:"kind,omitempty"`
	Summary          *apicheckpoint.Summary `json:"summary,omitempty"`
}

func (s *store) writeSession(ctx context.Context, opts apicheckpoint.WriteOptions) error {
	doc := sessionDoc{
		CheckpointID:     opts.CheckpointID,
		SessionID:        opts.SessionID,
		CreatedAt:        opts.CreatedAt,
		Strategy:         opts.Strategy,
		Branch:           opts.Branch,
		CommitSHA:        opts.CommitSHA,
		Prompts:          opts.Prompts,
		FilesTouched:     opts.FilesTouched,
		CheckpointsCount: opts.CheckpointsCount,
		AuthorName:       opts.AuthorName,
		AuthorEmail:      opts.AuthorEmail,
		Agent:            string(opts.Agent),
		Model:            opts.Model,
		Kind:             opts.Kind,
		Summary:          opts.Summary,
	}
	base := path.Join(s.objectPrefix(opts.CheckpointID), "sessions", sessionObjectStem(opts.SessionID))
	if err := s.putJSON(ctx, base+".json", doc); err != nil {
		return err
	}
	if opts.Transcript.Len() > 0 {
		if err := s.putBytes(ctx, base+".transcript.jsonl", opts.Transcript.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) writeTranscriptUpdate(ctx context.Context, opts apicheckpoint.UpdateOptions) error {
	base := path.Join(s.objectPrefix(opts.CheckpointID), "sessions", sessionObjectStem(opts.SessionID))
	if opts.Transcript.Len() > 0 {
		if err := s.putBytes(ctx, base+".transcript.jsonl", opts.Transcript.Bytes()); err != nil {
			return err
		}
	}
	if len(opts.Prompts) > 0 {
		if err := s.putJSON(ctx, base+".prompts.json", opts.Prompts); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) writeSummary(ctx context.Context, checkpointID id.CheckpointID, summary *apicheckpoint.Summary) error {
	if summary == nil {
		return nil
	}
	object := path.Join(s.objectPrefix(checkpointID), "summary.json")
	return s.putJSON(ctx, object, summary)
}

// taskDoc mirrors the stable fields of a TaskPayload a reader cares about;
// it drops Transcript, which is uploaded as its own object (same reasoning as
// the session transcript in writeSession).
type taskDoc struct {
	ToolUseID       string    `json:"tool_use_id"`
	AgentID         string    `json:"agent_id,omitempty"`
	SubagentType    string    `json:"subagent_type,omitempty"`
	TaskDescription string    `json:"task_description,omitempty"`
	Files           []string  `json:"files,omitempty"`
	StartedAt       time.Time `json:"started_at,omitzero"`
	CompletedAt     time.Time `json:"completed_at,omitzero"`
}

func (s *store) writeTasks(ctx context.Context, req apicheckpoint.Tasks) error {
	for _, t := range req.Tasks {
		base := path.Join(s.objectPrefix(req.CheckpointID), "tasks", t.ToolUseID)
		doc := taskDoc{
			ToolUseID:       t.ToolUseID,
			AgentID:         t.AgentID,
			SubagentType:    t.SubagentType,
			TaskDescription: t.TaskDescription,
			Files:           t.Files,
			StartedAt:       t.StartedAt,
			CompletedAt:     t.CompletedAt,
		}
		if err := s.putJSON(ctx, base+".json", doc); err != nil {
			return err
		}
		if t.Transcript.Len() > 0 {
			if err := s.putBytes(ctx, base+".transcript.jsonl", t.Transcript.Bytes()); err != nil {
				return err
			}
		}
	}
	return nil
}

func sessionObjectStem(sessionID string) string {
	if sessionID == "" {
		return "session"
	}
	return "session-" + sessionID
}

func (s *store) putJSON(ctx context.Context, object string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("gcs checkpoint mirror: marshal %s: %w", object, err)
	}
	return s.putBytes(ctx, object, data)
}

func (s *store) putBytes(ctx context.Context, object string, data []byte) error {
	if s.aead != nil {
		data, err := s.encrypt(data)
		if err != nil {
			return fmt.Errorf("gcs checkpoint mirror: encrypt %s: %w", object, err)
		}
		return s.upload(ctx, object, data)
	}
	return s.upload(ctx, object, data)
}

const (
	defaultBaseURL = "https://storage.googleapis.com"
	storageScope   = "https://www.googleapis.com/auth/devstorage.read_write"
	uploadTimeout  = 60 * time.Second
	// maxErrorBody bounds how much of a non-2xx response is echoed into the
	// error, so a misbehaving endpoint cannot bloat logs.
	maxErrorBody = 512
)

// upload performs a single-request "media" upload to the GCS JSON API:
// POST /upload/storage/v1/b/<bucket>/o?uploadType=media&name=<object>.
// Objects here are small (JSON docs and transcripts), so resumable uploads
// are not needed.
func (s *store) upload(ctx context.Context, object string, data []byte) error {
	endpoint := fmt.Sprintf("%s/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
		s.baseURL, url.PathEscape(s.bucket), url.QueryEscape(object))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gcs checkpoint mirror: build request for gs://%s/%s: %w", s.bucket, object, err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("gcs checkpoint mirror: write gs://%s/%s: %w", s.bucket, object, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		if readErr != nil {
			return fmt.Errorf("gcs checkpoint mirror: write gs://%s/%s: %s (reading response body: %w)", s.bucket, object, resp.Status, readErr)
		}
		return fmt.Errorf("gcs checkpoint mirror: write gs://%s/%s: %s: %s", s.bucket, object, resp.Status, body)
	}
	return nil
}

// encrypt prefixes a fresh random nonce to the AES-GCM sealed output, so
// decryption only needs the key plus the object's own bytes.
func (s *store) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}
