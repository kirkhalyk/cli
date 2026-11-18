package checkpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-git/go-git/v6/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/entireio/cli/cmd/entire/cli/checkpoint/id"
	"github.com/entireio/cli/cmd/entire/cli/paths"
	"github.com/entireio/cli/cmd/entire/cli/settings"
)

const fakeMirrorBackendType = "faketest-mirror"

var fakeMirrorBackendOnce sync.Once

// registerFakeMirrorBackend registers a non-git backend so mirror-selection
// paths can be exercised without the real fsstore. Registration is process-wide
// and idempotent (Register panics on duplicates).
func registerFakeMirrorBackend(t *testing.T) {
	t.Helper()
	fakeMirrorBackendOnce.Do(func() {
		Register(fakeMirrorBackendType, func(_ context.Context, _ OpenEnv, _ json.RawMessage) (PersistentStore, error) {
			return &fakePrimary{}, nil
		})
	})
}

func writeRawSettings(t *testing.T, dir, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".entire"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".entire", paths.SettingsFileName), []byte(body), 0o644))
}

// Not parallel: uses t.Chdir so settings resolve to the test repo.
func TestOpen_DefaultIsGitPrimaryNoMirrors(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)

	stores, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)
	// Persistent is always the kind-routing store now (it routes id-keyed reads
	// across the git backends); with a git-branch primary it preserves the git
	// AuthorReader capability.
	_, isRouting := stores.Persistent.(*kindRoutingStoreWithAuthor)
	assert.True(t, isRouting, "default persistent store should be the kind-routing store")
	_, isAuthor := stores.Persistent.(AuthorReader)
	assert.True(t, isAuthor, "routing store should preserve the git primary's AuthorReader")
}

// Under a git-refs primary, a write to a hex checkpoint still on v1 copies it
// into its own ref. The copy needs the router to hold the built-in git stores
// and the caller's remote probe; without them those writes silently go back to
// v1, which git-refs never pushes.
// Not parallel: uses t.Chdir so settings resolve to the test repo.
func TestOpen_RefsPrimaryRouterCopiesLegacyCheckpoints(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	ctx := context.Background()
	cid := id.MustCheckpointID(legacyCopyID)
	writeRoutingCheckpoint(t, NewGitStore(repo, DefaultV1Refs()), cid, "before-switch")
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "`+BackendTypeGitRefs+`"}}}`)
	var probed []plumbing.ReferenceName

	stores, err := Open(ctx, repo, OpenOptions{
		LegacyCopyRefFetcher: func(_ context.Context, ref plumbing.ReferenceName) error {
			probed = append(probed, ref)
			return fmt.Errorf("probe remote: %w", plumbing.ErrReferenceNotFound)
		},
	})
	require.NoError(t, err)
	require.NoError(t, stores.Persistent.Write(ctx, afterSwitchSession(cid)))

	refName, err := RefName(cid)
	require.NoError(t, err)
	assert.Equal(t, []plumbing.ReferenceName{refName}, probed, "the copy must ask the remote with the caller's probe")
	_, err = repo.Reference(refName, true)
	require.NoError(t, err, "the write must copy the v1-only checkpoint into its own ref")
}

func TestOpen_RejectsNonGitBackedPrimary(t *testing.T) {
	registerFakeMirrorBackend(t) // a registered, non-git-backed backend
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "`+fakeMirrorBackendType+`"}}}`)

	_, err := Open(context.Background(), repo, OpenOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be the primary")
	assert.Contains(t, err.Error(), "git-backed")
}

func TestOpen_RejectsUnknownPrimary(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "nope"}}}`)

	_, err := Open(context.Background(), repo, OpenOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown checkpoint backend type")
}

func TestOpen_RejectsMirrorOfPrimaryType(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	// A git-branch mirror under a git-branch primary would double-write v1.
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"type": "git-branch"}]}}`)

	_, err := Open(context.Background(), repo, OpenOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most once")
}

func TestOpen_RejectsDuplicateMirrorType(t *testing.T) {
	registerFakeMirrorBackend(t)
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	// Two mirrors of the same type are rejected (one of each type).
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"type": "`+fakeMirrorBackendType+`"}, {"type": "`+fakeMirrorBackendType+`"}]}}`)

	_, err := Open(context.Background(), repo, OpenOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most once")
}

func TestOpen_BuildsConfiguredMirror(t *testing.T) {
	registerFakeMirrorBackend(t)
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"type": "`+fakeMirrorBackendType+`"}]}}`)

	stores, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)

	// The persistent store is the kind-routing store (never the raw git store),
	// and it still exposes AuthorReader (git primary has it).
	_, isGit := stores.Persistent.(*GitStore)
	assert.False(t, isGit, "configured mirror should not expose the raw git store")
	_, isAuthor := stores.Persistent.(AuthorReader)
	assert.True(t, isAuthor, "routing store should preserve the git primary's AuthorReader")
}

func TestOpen_InvalidCheckpointsBlockErrors(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	// Present checkpoints block, but a mirror with no type is invalid.
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"config": {}}]}}`)

	_, err := Open(context.Background(), repo, OpenOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checkpoints")
}

func TestOpen_ToleratesUnrelatedMalformedSettings(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	// summary_generation is the wrong shape and the JSON has no checkpoints
	// block: checkpoint construction must stay fail-soft and default to git.
	writeRawSettings(t, dir, `{"enabled": true, "summary_generation": "not-an-object"}`)

	stores, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)
	// Fail-soft default is the git-branch backend, so the routing store still
	// exposes the git AuthorReader capability.
	_, isAuthor := stores.Persistent.(AuthorReader)
	assert.True(t, isAuthor)
}

func TestOpen_ToleratesWholeFileSyntaxError(t *testing.T) {
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	writeRawSettings(t, dir, `{"enabled": true,,}`) // invalid JSON

	stores, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)
	// Fail-soft default is the git-branch backend, so the routing store still
	// exposes the git AuthorReader capability.
	_, isAuthor := stores.Persistent.(AuthorReader)
	assert.True(t, isAuthor)
}

const (
	fakeOffMachineBackendType = "faketest-offmachine"
	fakeBrokenBackendType     = "faketest-broken"
)

var (
	fakeGatedBackendsOnce  sync.Once
	fakeOffMachineFactoryN atomic.Int32
)

// registerFakeGatedBackends registers an off-machine backend (counting factory
// calls, so a test can tell whether buildMirrors reached it) and a backend whose
// construction always fails, like a gcs mirror without its key or credentials.
func registerFakeGatedBackends(t *testing.T) {
	t.Helper()
	fakeGatedBackendsOnce.Do(func() {
		RegisterOffMachine(fakeOffMachineBackendType, func(_ context.Context, _ OpenEnv, _ json.RawMessage) (PersistentStore, error) {
			fakeOffMachineFactoryN.Add(1)
			return &fakePrimary{}, nil
		})
		Register(fakeBrokenBackendType, func(_ context.Context, _ OpenEnv, _ json.RawMessage) (PersistentStore, error) {
			return nil, errors.New("encryption key env var is not set")
		})
	})
}

func writeRawLocalSettings(t *testing.T, dir, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".entire"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(settings.EntireSettingsLocalFile)), []byte(body), 0o644))
}

// A mirror that cannot be constructed (missing key, no credentials) is dropped
// best-effort; it must not fail Open and with it every checkpoint operation.
func TestOpen_SkipsMirrorWhoseConstructionFails(t *testing.T) {
	registerFakeGatedBackends(t)
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"type": "`+fakeBrokenBackendType+`"}]}}`)

	stores, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)
	require.NotNil(t, stores.Persistent)
}

// One JSON line in the version-controlled settings.json must not be able to
// send every teammate's checkpoints off the machine.
func TestOpen_OffMachineMirrorRefusedFromTrackedSettings(t *testing.T) {
	registerFakeGatedBackends(t)
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	writeRawSettings(t, dir, `{"enabled": true, "checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"type": "`+fakeOffMachineBackendType+`"}]}}`)

	before := fakeOffMachineFactoryN.Load()
	_, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)
	assert.Equal(t, before, fakeOffMachineFactoryN.Load(), "off-machine mirror must not be built from settings.json")
}

func TestOpen_OffMachineMirrorBuiltFromUntrackedLocalSettings(t *testing.T) {
	registerFakeGatedBackends(t)
	dir, repo, _ := newTestRepo(t)
	t.Chdir(dir)
	settings.ClearVersionedPathCache()
	writeRawLocalSettings(t, dir, `{"checkpoints": {"primary": {"type": "git-branch"}, "mirrors": [{"type": "`+fakeOffMachineBackendType+`"}]}}`)

	before := fakeOffMachineFactoryN.Load()
	_, err := Open(context.Background(), repo, OpenOptions{})
	require.NoError(t, err)
	assert.Equal(t, before+1, fakeOffMachineFactoryN.Load(), "off-machine mirror should be built from an untracked settings.local.json")
}
