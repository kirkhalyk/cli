package gcsmirror

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/entireio/cli/cmd/entire/cli/checkpoint"
	"github.com/entireio/cli/cmd/entire/cli/checkpoint/id"
)

func TestObjectPrefixSharding(t *testing.T) {
	t.Parallel()
	cpID, err := id.GenerateULID()
	if err != nil {
		t.Fatalf("generate ULID: %v", err)
	}
	s := &store{prefix: "entire"}
	got := s.objectPrefix(cpID)
	want := "entire/checkpoints/" + cpID.ShardFor() + "/" + cpID.String()
	if got != want {
		t.Errorf("objectPrefix(%s) = %q, want %q", cpID, got, want)
	}
}

func TestEncryptRoundTripBindsObjectName(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const envVar = "ENTIRE_GCS_MIRROR_TEST_KEY"
	t.Setenv(envVar, base64.StdEncoding.EncodeToString(key))

	aead, keyID, err := aeadFromEnv(envVar)
	if err != nil {
		t.Fatalf("aeadFromEnv: %v", err)
	}
	s := &store{aead: aead, keyID: keyID}

	const objA = "entire/checkpoints/ab/x/sessions/session-a.transcript.jsonl"
	const objB = "entire/checkpoints/ab/x/sessions/session-b.transcript.jsonl"
	plaintext := []byte("hello from a checkpoint transcript")
	sealed, err := s.encrypt(objA, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	headerLen := 1 + keyIDSize
	if sealed[0] != formatV1 {
		t.Fatalf("format byte = %#x, want %#x", sealed[0], formatV1)
	}
	if !bytes.Equal(sealed[1:headerLen], keyFingerprint(key)) {
		t.Fatal("header does not carry the key fingerprint")
	}
	header := sealed[:headerLen]
	nonce := sealed[headerLen : headerLen+aead.NonceSize()]
	body := sealed[headerLen+aead.NonceSize():]

	opened, err := aead.Open(nil, nonce, body, associatedData(header, objA))
	if err != nil {
		t.Fatalf("decrypt under its own name: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", opened, plaintext)
	}

	// A ciphertext copied to another object name must not authenticate.
	if _, err := aead.Open(nil, nonce, body, associatedData(header, objB)); err == nil {
		t.Error("ciphertext opened under a different object name; AAD does not bind the name")
	}
}

func TestAeadFromEnvRejectsBadKey(t *testing.T) {
	const envVar = "ENTIRE_GCS_MIRROR_TEST_BADKEY"

	t.Run("unset", func(t *testing.T) {
		t.Setenv(envVar, "")
		if _, _, err := aeadFromEnv(envVar); err == nil {
			t.Error("expected error for unset env var")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Setenv(envVar, base64.StdEncoding.EncodeToString([]byte("too-short")))
		if _, _, err := aeadFromEnv(envVar); err == nil {
			t.Error("expected error for short key")
		}
	})

	t.Run("not base64", func(t *testing.T) {
		t.Setenv(envVar, "not-valid-base64!!!")
		if _, _, err := aeadFromEnv(envVar); err == nil {
			t.Error("expected error for invalid base64")
		}
	})
}

func TestFactoryRequiresBucket(t *testing.T) {
	t.Parallel()
	if _, err := factory(context.Background(), checkpoint.OpenEnv{}, nil); err == nil {
		t.Error("expected error when config.bucket is missing")
	}
}

// The factory must not resolve Google credentials: checkpoint.Open runs for
// read-only commands, and a missing ADC must not fail it.
func TestFactoryDefersCredentials(t *testing.T) {
	t.Parallel()
	ps, err := factory(context.Background(), checkpoint.OpenEnv{}, []byte(`{"bucket":"b"}`))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if s, ok := ps.(*store); !ok || s.client != nil {
		t.Errorf("factory resolved an HTTP client eagerly: %#v", ps)
	}
}

func TestRegisterIsIdempotent(t *testing.T) {
	t.Parallel()
	Register()
	Register() // checkpoint.Register would panic on a duplicate type
}

// awsKeyFixture is an AWS-Access-Key-ID-shaped value for exercising redaction.
// Assembled rather than one literal so the pattern stays off disk; see
// redact.awsKeyFixture in redact/redact_test.go. Do not re-inline it.
const awsKeyFixture = "AKIAYRWQG5" + "EJLPZLBYNP"

// recordingServer captures every uploaded object by name.
func recordingServer(t *testing.T) (*store, map[string]string) {
	t.Helper()
	var mu sync.Mutex
	objects := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		objects[r.URL.Query().Get("name")] = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return &store{client: srv.Client(), baseURL: srv.URL, bucket: "b", prefix: "entire"}, objects
}

func newCheckpointID(t *testing.T) id.CheckpointID {
	t.Helper()
	cpID, err := id.GenerateULID()
	if err != nil {
		t.Fatalf("generate ULID: %v", err)
	}
	return cpID
}

// WriteOptions carries raw prompts and free text and leaves redaction to the
// writer; the mirror must redact exactly as the git writer and fsstore do.
func TestWriteRedactsFreeText(t *testing.T) {
	t.Parallel()
	s, objects := recordingServer(t)
	cpID := newCheckpointID(t)

	err := s.Write(context.Background(), checkpoint.Session{
		CheckpointID:     cpID,
		SessionID:        "sess-1",
		Prompts:          []string{"deploy with key " + awsKeyFixture},
		ReviewPrompt:     "review " + awsKeyFixture,
		InvestigateTopic: "why " + awsKeyFixture,
		Summary:          &checkpoint.Summary{Intent: "rotate " + awsKeyFixture},
		Tasks: []checkpoint.TaskPayload{{
			ToolUseID:       "toolu_01",
			TaskDescription: "use " + awsKeyFixture,
		}},
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Write(context.Background(), checkpoint.SessionTranscript{
		CheckpointID: cpID,
		SessionID:    "sess-1",
		Prompts:      []string{"again " + awsKeyFixture},
	}); err != nil {
		t.Fatalf("Write transcript update: %v", err)
	}
	if err := s.Write(context.Background(), checkpoint.SessionSummary{
		CheckpointID: cpID,
		Summary:      &checkpoint.Summary{Outcome: "done " + awsKeyFixture},
	}); err != nil {
		t.Fatalf("Write summary: %v", err)
	}

	if len(objects) == 0 {
		t.Fatal("no objects uploaded")
	}
	for name, body := range objects {
		if strings.Contains(body, awsKeyFixture) {
			t.Errorf("object %s contains an unredacted secret: %s", name, body)
		}
	}
	// Tasks carried inline on a Session write are materialized.
	taskObj := s.objectPrefix(cpID) + "/tasks/toolu_01.json"
	if _, ok := objects[taskObj]; !ok {
		t.Errorf("inline task not uploaded; got objects %v", keys(objects))
	}
}

// IDs become object-name segments and path.Join resolves "../", so an
// unvalidated ID could write outside the checkpoint's prefix.
func TestWriteRejectsPathTraversalIDs(t *testing.T) {
	t.Parallel()
	s, objects := recordingServer(t)
	cpID := newCheckpointID(t)

	if err := s.Write(context.Background(), checkpoint.Session{
		CheckpointID: cpID,
		SessionID:    "../../../other-team/x",
	}); err == nil {
		t.Error("expected an error for a traversal session ID")
	}
	if err := s.Write(context.Background(), checkpoint.Tasks{
		CheckpointID: cpID,
		Tasks:        []checkpoint.TaskPayload{{ToolUseID: "../../x"}},
	}); err == nil {
		t.Error("expected an error for a traversal tool use ID")
	}
	if err := s.Write(context.Background(), checkpoint.Tasks{
		CheckpointID: cpID,
		Tasks:        []checkpoint.TaskPayload{{ToolUseID: ""}},
	}); err == nil {
		t.Error("expected an error for an empty tool use ID")
	}
	if len(objects) != 0 {
		t.Errorf("uploads happened despite invalid IDs: %v", keys(objects))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestUploadSendsMediaUpload(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath, gotName, gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotName = r.URL.Query().Get("name")
		gotType = r.URL.Query().Get("uploadType")
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	s := &store{client: srv.Client(), baseURL: srv.URL, bucket: "my-bucket", prefix: "entire"}
	const object = "entire/checkpoints/ab/abcdef/session-x.json"
	if err := s.upload(context.Background(), object, []byte(`{"k":"v"}`)); err != nil {
		t.Fatalf("upload: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/upload/storage/v1/b/my-bucket/o"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotType != "media" {
		t.Errorf("uploadType = %q, want media", gotType)
	}
	if gotName != object {
		t.Errorf("name = %q, want %q", gotName, object)
	}
	if gotBody != `{"k":"v"}` {
		t.Errorf("body = %q", gotBody)
	}
}

func TestUploadReportsHTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bucket not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	s := &store{client: srv.Client(), baseURL: srv.URL, bucket: "nope"}
	err := s.upload(context.Background(), "obj", []byte("x"))
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "bucket not found") {
		t.Errorf("error should include status and body, got: %v", err)
	}
}
