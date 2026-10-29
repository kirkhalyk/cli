package gcsmirror

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestAeadFromEnvRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const envVar = "ENTIRE_GCS_MIRROR_TEST_KEY"
	t.Setenv(envVar, base64.StdEncoding.EncodeToString(key))

	aead, err := aeadFromEnv(envVar)
	if err != nil {
		t.Fatalf("aeadFromEnv: %v", err)
	}
	s := &store{aead: aead}

	plaintext := []byte("hello from a checkpoint transcript")
	ciphertext, err := s.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Fatal("encrypt returned plaintext unchanged")
	}

	nonce := ciphertext[:aead.NonceSize()]
	opened, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", opened, plaintext)
	}
}

func TestAeadFromEnvRejectsBadKey(t *testing.T) {
	const envVar = "ENTIRE_GCS_MIRROR_TEST_BADKEY"

	t.Run("unset", func(t *testing.T) {
		t.Setenv(envVar, "")
		if _, err := aeadFromEnv(envVar); err == nil {
			t.Error("expected error for unset env var")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Setenv(envVar, base64.StdEncoding.EncodeToString([]byte("too-short")))
		if _, err := aeadFromEnv(envVar); err == nil {
			t.Error("expected error for short key")
		}
	})

	t.Run("not base64", func(t *testing.T) {
		t.Setenv(envVar, "not-valid-base64!!!")
		if _, err := aeadFromEnv(envVar); err == nil {
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

func TestSessionObjectStem(t *testing.T) {
	t.Parallel()
	if got := sessionObjectStem(""); got != "session" {
		t.Errorf("sessionObjectStem(\"\") = %q, want %q", got, "session")
	}
	if got := sessionObjectStem("abc123"); got != "session-abc123" {
		t.Errorf("sessionObjectStem(%q) = %q, want %q", "abc123", got, "session-abc123")
	}
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
