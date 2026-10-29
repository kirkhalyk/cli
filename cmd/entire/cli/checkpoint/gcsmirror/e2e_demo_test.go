package gcsmirror

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/entireio/cli/cmd/entire/cli/checkpoint"
	"github.com/entireio/cli/cmd/entire/cli/gitrepo"
	"github.com/entireio/cli/cmd/entire/cli/testutil"
)

// TestManualEndToEndDemo is not part of the normal suite — it needs real
// network access to the GCS API, which CI does not grant. Run with:
//
//	go test ./... -run TestManualEndToEndDemo -v -tags manual
//
// It demonstrates (not asserts — the bucket in the demo config is
// intentionally fake and no credentials are provided) that:
//   - a "gcs" mirror in .entire/settings.json is resolved through the real
//     registry (no "unknown checkpoint backend" error);
//   - the primary git-refs write still succeeds even though the mirror write
//     fails (fanoutStore.Write's best-effort swallow).
//
// Uses t.Chdir, so per AGENTS.md's test-safety rule it does not call
// t.Parallel().
func TestManualEndToEndDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("manual demo: needs live network access to the GCS API")
	}

	Register()

	dir := t.TempDir()
	testutil.InitRepo(t, dir)
	testutil.WriteFile(t, dir, "README.md", "# gcsmirror demo\n")
	testutil.WriteFile(t, dir, ".entire/settings.json", `{
  "enabled": true,
  "checkpoints": {
    "primary": { "type": "git-refs" },
    "mirrors": [
      {
        "type": "gcs",
        "config": {
          "bucket": "does-not-exist-prototype-bucket",
          "prefix": "entire-demo",
          "encryption_key_env": "ENTIRE_GCS_MIRROR_DEMO_KEY"
        }
      }
    ]
  }
}`)
	testutil.GitAdd(t, dir, "README.md", ".entire/settings.json")
	testutil.GitCommit(t, dir, "init")

	key := make([]byte, 32)
	t.Setenv("ENTIRE_GCS_MIRROR_DEMO_KEY", base64.StdEncoding.EncodeToString(key))
	t.Chdir(dir)

	repo, err := gitrepo.OpenPath(dir)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	stores, err := checkpoint.Open(ctx, repo, checkpoint.OpenOptions{})
	if err != nil {
		t.Fatalf("checkpoint.Open: %v", err)
	}
	t.Logf("opened store; primaryIsRefs=%v", stores.PrimaryIsRefs())

	cpID, err := checkpoint.GenerateCheckpointID(ctx)
	if err != nil {
		t.Fatalf("generate checkpoint id: %v", err)
	}

	writeErr := stores.Persistent.Write(ctx, checkpoint.Session{
		CheckpointID: cpID,
		SessionID:    "gcsmirror-demo-session",
		CreatedAt:    time.Now(),
		Strategy:     "manual-demo",
		Prompts:      []string{"demonstrate the gcs checkpoint mirror prototype"},
	})
	t.Logf("checkpoint %s write result: %v", cpID, writeErr)
	if writeErr != nil {
		t.Fatalf("primary write (git-refs) should succeed even though the gcs mirror is unreachable: %v", writeErr)
	}
}
