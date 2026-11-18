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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"golang.org/x/oauth2/google"

	apicheckpoint "github.com/entireio/cli/api/checkpoint"
	"github.com/entireio/cli/cmd/entire/cli/agent/types"
	"github.com/entireio/cli/cmd/entire/cli/checkpoint"
	"github.com/entireio/cli/cmd/entire/cli/checkpoint/id"
	"github.com/entireio/cli/cmd/entire/cli/validation"
	"github.com/entireio/cli/redact"
)

// BackendType is the name this backend registers under. Select it as a mirror
// via the checkpoints.mirrors block of an untracked .entire/settings.local.json
// (the version-controlled settings.json cannot enable an off-machine mirror):
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
// package must call it before any checkpoint.Open for the "gcs" mirror type to
// be selectable; omitting the call leaves "gcs" unknown, matching how every
// other non-built-in backend stays out of a binary that never registers it.
// It registers as an off-machine backend, so the mirror is only built from
// developer-owned config (env override or an untracked settings.local.json),
// never from the version-controlled settings.json. Idempotent, so tests and
// main can both call it (checkpoint.Register panics on a duplicate type).
func Register() {
	registerOnce.Do(func() {
		checkpoint.RegisterOffMachine(BackendType, factory)
	})
}

var registerOnce sync.Once

// Config is the backend-specific "config" block for the "gcs" mirror.
type Config struct {
	// Bucket is the GCS bucket name (no gs:// prefix).
	Bucket string `json:"bucket"`

	// Prefix is an optional object-name prefix, so one bucket can host several
	// repos' or teams' checkpoints without colliding. Defaults to "entire".
	Prefix string `json:"prefix,omitempty"`

	// EncryptionKeyEnv names an environment variable holding a base64-encoded
	// 32-byte AES-256 key. When set, every uploaded object is encrypted with
	// it before upload (AES-256-GCM; see encrypt for the object format).
	// When empty, objects are uploaded as plaintext JSON/bytes — only do that
	// for a bucket you otherwise trust, e.g. one already restricted to the
	// team and encrypted at rest by GCS itself.
	EncryptionKeyEnv string `json:"encryption_key_env,omitempty"`
}

// factory validates config and the encryption key (both cheap and local) but
// does not resolve Google credentials: checkpoint.Open runs for read-only
// commands too, and resolving Application Default Credentials there would cost
// a GCE metadata-server probe on every `entire explain` for a backend that
// only ever writes. Credentials are resolved on the first Write instead.
func factory(_ context.Context, _ checkpoint.OpenEnv, raw json.RawMessage) (checkpoint.PersistentStore, error) {
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

	s := &store{
		baseURL: defaultBaseURL,
		bucket:  cfg.Bucket,
		prefix:  cfg.Prefix,
	}
	if cfg.EncryptionKeyEnv != "" {
		aead, keyID, err := aeadFromEnv(cfg.EncryptionKeyEnv)
		if err != nil {
			return nil, fmt.Errorf("gcs checkpoint mirror: %w", err)
		}
		s.aead, s.keyID = aead, keyID
	}
	return s, nil
}

// aeadFromEnv reads a base64-encoded 32-byte key from the named environment
// variable and builds an AES-256-GCM AEAD from it. It also returns the key's
// fingerprint (see keyFingerprint), written into every object header so a
// reader holding several keys across a rotation can pick the right one.
func aeadFromEnv(envVar string) (cipher.AEAD, []byte, error) {
	encoded := os.Getenv(envVar)
	if encoded == "" {
		return nil, nil, fmt.Errorf("encryption key env var %q is not set", envVar)
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("encryption key env var %q is not valid base64: %w", envVar, err)
	}
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("encryption key env var %q must decode to 32 bytes (AES-256), got %d", envVar, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("build AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("build AES-GCM AEAD: %w", err)
	}
	return gcm, keyFingerprint(key), nil
}

// keyFingerprint identifies a key without revealing it: the first
// keyIDSize bytes of its SHA-256. 64 bits is plenty to tell a team's handful
// of rotated keys apart and leaks nothing usable about a 256-bit key.
func keyFingerprint(key []byte) []byte {
	sum := sha256.Sum256(key)
	return sum[:keyIDSize]
}

// store is the "gcs" checkpoint mirror. It satisfies checkpoint.PersistentStore
// so it can be constructed through the same registry as any other backend, but
// only Write is ever exercised in practice: the fan-out store that wires
// mirrors (checkpoint.newFanoutStore) never routes reads to one. The Read*/
// List* methods below return clear errors rather than silently fabricating
// empty results, so a bug that did call them would fail loudly instead of
// looking like "checkpoint not found".
type store struct {
	// client is the authenticated HTTP client. Unit tests set it directly;
	// otherwise httpClient resolves Application Default Credentials into it
	// on first use.
	client     *http.Client
	clientErr  error
	clientOnce sync.Once
	// baseURL is the GCS JSON API origin; overridable for tests.
	baseURL string
	bucket  string
	prefix  string
	// aead encrypts every object this store writes when non-nil. nil means
	// objects are uploaded as plaintext.
	aead cipher.AEAD
	// keyID is aead's key fingerprint, written into each object header.
	keyID []byte
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
// pattern. Each case uploads one or more objects under
// objectPrefix(checkpointID)/.
//
// The whole call shares one writeBudget deadline. Mirror writes run
// synchronously on the commit path (fanoutStore.Write), so an unreachable or
// slow endpoint must cost the user a bounded few seconds, not one full request
// timeout per object.
func (s *store) Write(ctx context.Context, req apicheckpoint.WriteRequest) error {
	ctx, cancel := context.WithTimeout(ctx, writeBudget)
	defer cancel()

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
		return s.writeTasks(ctx, r.CheckpointID, r.Tasks)
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
//
// Every free-text field is redacted exactly as the git writer and fsstore
// redact it: WriteOptions carries raw prompts and review/investigate text and
// leaves redaction to the writer, and a mirror is a writer.
type sessionDoc struct {
	CheckpointID     id.CheckpointID        `json:"checkpoint_id"`
	SessionID        string                 `json:"session_id"`
	CreatedAt        time.Time              `json:"created_at"`
	Strategy         string                 `json:"strategy,omitempty"`
	Branch           string                 `json:"branch,omitempty"`
	CommitSHA        string                 `json:"commit_sha,omitempty"`
	Prompts          string                 `json:"prompts,omitempty"`
	FilesTouched     []string               `json:"files_touched,omitempty"`
	CheckpointsCount int                    `json:"checkpoints_count,omitempty"`
	AuthorName       string                 `json:"author_name,omitempty"`
	AuthorEmail      string                 `json:"author_email,omitempty"`
	Agent            string                 `json:"agent,omitempty"`
	Model            string                 `json:"model,omitempty"`
	Kind             string                 `json:"kind,omitempty"`
	Summary          *apicheckpoint.Summary `json:"summary,omitempty"`
	ReviewPrompt     string                 `json:"review_prompt,omitempty"`
	InvestigateTopic string                 `json:"investigate_topic,omitempty"`
}

func (s *store) writeSession(ctx context.Context, opts apicheckpoint.WriteOptions) error {
	base, err := s.sessionBase(opts.CheckpointID, opts.SessionID)
	if err != nil {
		return err
	}
	doc := sessionDoc{
		CheckpointID:     opts.CheckpointID,
		SessionID:        opts.SessionID,
		CreatedAt:        opts.CreatedAt,
		Strategy:         opts.Strategy,
		Branch:           opts.Branch,
		CommitSHA:        opts.CommitSHA,
		Prompts:          redactedPrompts(opts.Prompts),
		FilesTouched:     opts.FilesTouched,
		CheckpointsCount: opts.CheckpointsCount,
		AuthorName:       opts.AuthorName,
		AuthorEmail:      opts.AuthorEmail,
		Agent:            string(opts.Agent),
		Model:            opts.Model,
		Kind:             opts.Kind,
		Summary:          checkpoint.RedactSummary(opts.Summary),
		ReviewPrompt:     redact.String(opts.ReviewPrompt),
		InvestigateTopic: redact.String(opts.InvestigateTopic),
	}
	if err := s.putJSON(ctx, base+".json", doc); err != nil {
		return err
	}

	transcript := opts.Transcript
	if transcript.Len() == 0 && opts.TranscriptPath != "" {
		// Same store-reads-and-redacts fallback the git writer takes.
		if transcript, err = checkpoint.ReadRedactedTranscriptFile(ctx, opts.Agent, opts.TranscriptPath); err != nil {
			return fmt.Errorf("gcs checkpoint mirror: %w", err)
		}
	}
	if err := s.putTranscript(ctx, base, opts.Agent, transcript); err != nil {
		return err
	}
	// A Session write can carry its subagent tasks inline; the git writer and
	// fsstore materialize them, so the mirror must too.
	return s.writeTasks(ctx, opts.CheckpointID, opts.Tasks)
}

func (s *store) writeTranscriptUpdate(ctx context.Context, opts apicheckpoint.UpdateOptions) error {
	base, err := s.sessionBase(opts.CheckpointID, opts.SessionID)
	if err != nil {
		return err
	}
	if err := s.putTranscript(ctx, base, opts.Agent, opts.Transcript); err != nil {
		return err
	}
	if len(opts.Prompts) > 0 {
		if err := s.putBytes(ctx, base+".prompts.txt", []byte(redactedPrompts(opts.Prompts))); err != nil {
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
	return s.putJSON(ctx, object, checkpoint.RedactSummary(summary))
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

func (s *store) writeTasks(ctx context.Context, checkpointID id.CheckpointID, tasks []apicheckpoint.TaskPayload) error {
	for _, t := range tasks {
		// The tool use ID becomes an object-name segment; path.Join would
		// resolve a "../" in it out of this checkpoint's prefix.
		if t.ToolUseID == "" {
			return errors.New("gcs checkpoint mirror: task has an empty tool use ID")
		}
		if err := validation.ValidateToolUseID(t.ToolUseID); err != nil {
			return fmt.Errorf("gcs checkpoint mirror: %w", err)
		}
		base := path.Join(s.objectPrefix(checkpointID), "tasks", t.ToolUseID)
		doc := taskDoc{
			ToolUseID:       t.ToolUseID,
			AgentID:         t.AgentID,
			SubagentType:    t.SubagentType,
			TaskDescription: redact.String(t.TaskDescription),
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

// sessionBase returns the object-name stem for a session's objects. The
// session ID becomes an object-name segment, and path.Join resolves "../", so
// an unvalidated ID could write outside this checkpoint's prefix — into
// another repo's or team's objects in a shared bucket.
func (s *store) sessionBase(checkpointID id.CheckpointID, sessionID string) (string, error) {
	stem := "session"
	if sessionID != "" {
		if err := validation.ValidateSessionID(sessionID); err != nil {
			return "", fmt.Errorf("gcs checkpoint mirror: %w", err)
		}
		stem = "session-" + sessionID
	}
	return path.Join(s.objectPrefix(checkpointID), "sessions", stem), nil
}

// redactedPrompts joins and redacts prompts through the same pipeline the git
// writer uses for prompt.txt, so the mirror holds identically-redacted text.
func redactedPrompts(prompts []string) string {
	if len(prompts) == 0 {
		return ""
	}
	return checkpoint.RedactedJoinedPrompts(prompts)
}

// putTranscript uploads an already-redacted session transcript, after the same
// idempotent sanitize safety net the git writer applies for callers (notably
// `entire import`) that reach the store without sanitizing.
func (s *store) putTranscript(ctx context.Context, base string, agentType types.AgentType, transcript redact.RedactedBytes) error {
	if transcript.Len() == 0 {
		return nil
	}
	data := checkpoint.SanitizeTranscriptForAgentType(agentType, transcript.Bytes())
	return s.putBytes(ctx, base+".transcript.jsonl", data)
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
		var err error
		if data, err = s.encrypt(object, data); err != nil {
			return fmt.Errorf("gcs checkpoint mirror: encrypt %s: %w", object, err)
		}
	}
	return s.upload(ctx, object, data)
}

const (
	defaultBaseURL = "https://storage.googleapis.com"
	storageScope   = "https://www.googleapis.com/auth/devstorage.read_write"
	// requestTimeout bounds a single upload; writeBudget bounds a whole Write
	// (every object it uploads, plus the first-use credential lookup).
	requestTimeout = 10 * time.Second
	writeBudget    = 15 * time.Second
	// maxErrorBody bounds how much of a non-2xx response is echoed into the
	// error, so a misbehaving endpoint cannot bloat logs.
	maxErrorBody = 512
)

// httpClient returns the authenticated client, resolving Application Default
// Credentials on first use. The credential lookup is detached from the
// caller's cancellation: the token source keeps the context it was built with
// for every later refresh, and Write's context is cancelled when Write
// returns. Its deadline still bounds this first lookup via the caller's ctx
// on the request itself.
func (s *store) httpClient(ctx context.Context) (*http.Client, error) {
	s.clientOnce.Do(func() {
		if s.client != nil {
			return
		}
		client, err := google.DefaultClient(context.WithoutCancel(ctx), storageScope)
		if err != nil {
			s.clientErr = fmt.Errorf("gcs checkpoint mirror: application default credentials: %w", err)
			return
		}
		client.Timeout = requestTimeout
		s.client = client
	})
	return s.client, s.clientErr
}

// upload performs a single-request "media" upload to the GCS JSON API:
// POST /upload/storage/v1/b/<bucket>/o?uploadType=media&name=<object>.
// Objects here are small (JSON docs and transcripts), so resumable uploads
// are not needed.
func (s *store) upload(ctx context.Context, object string, data []byte) error {
	client, err := s.httpClient(ctx)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
		s.baseURL, url.PathEscape(s.bucket), url.QueryEscape(object))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gcs checkpoint mirror: build request for gs://%s/%s: %w", s.bucket, object, err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
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

// Encrypted object format, version 1:
//
//	version (1 byte, 0x01) || key ID (8 bytes) || nonce (12 bytes) || AES-GCM ciphertext+tag
//
// The associated data is the 9-byte header followed by the object name, so a
// ciphertext only opens under the name it was written to: copying one session's
// transcript over another's (possible for anyone with bucket write access but
// not the key) fails authentication instead of decrypting as the other
// session's data. The key ID lets a reader holding several keys across a
// rotation pick the right one.
const (
	formatV1  byte = 0x01
	keyIDSize int  = 8
)

// encrypt seals plaintext for object in the format above.
func (s *store) encrypt(object string, plaintext []byte) ([]byte, error) {
	header := make([]byte, 0, 1+keyIDSize)
	header = append(header, formatV1)
	header = append(header, s.keyID...)

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	out := make([]byte, 0, len(header)+len(nonce)+len(plaintext)+s.aead.Overhead())
	out = append(out, header...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, associatedData(header, object)), nil
}

func associatedData(header []byte, object string) []byte {
	ad := make([]byte, 0, len(header)+len(object))
	ad = append(ad, header...)
	return append(ad, object...)
}
