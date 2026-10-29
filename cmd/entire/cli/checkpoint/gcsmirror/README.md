# gcsmirror — GCS checkpoint mirror (prototype)

Fans out checkpoint writes to a Google Cloud Storage bucket, so a team can
share agent-session checkpoints through infrastructure they control instead
of (or alongside) Entire's own hosted service. No Entire account is needed:
auth is plain Google Application Default Credentials.

Registered as a **mirror-only** backend (`gitBacked: false` in the parent
`checkpoint` package's registry): it never serves reads and can never be the
primary. Git-refs (or git-branch) stays the source of truth; this backend
gets a best-effort copy of every write. A mirror write failure is logged and
swallowed by `fanoutStore.Write` — it can never break `entire` for the user,
even if the bucket is unreachable, misconfigured, or the key rotates.

## Wiring it into a build

```go
import "github.com/entireio/cli/cmd/entire/cli/checkpoint/gcsmirror"

func main() {
    gcsmirror.Register() // before any checkpoint.Open call
    ...
}
```

(Done in this prototype's `cmd/entire/main.go`.)

## Repo configuration

`.entire/settings.json`:

```json
{
  "checkpoints": {
    "primary": { "type": "git-refs" },
    "mirrors": [
      {
        "type": "gcs",
        "config": {
          "bucket": "my-team-checkpoints",
          "prefix": "entire",
          "encryption_key_env": "ENTIRE_GCS_MIRROR_KEY"
        }
      }
    ]
  }
}
```

- `bucket` (required) — GCS bucket name, no `gs://`.
- `prefix` (optional, default `"entire"`) — object-name prefix, so one bucket
  can host multiple repos/teams.
- `encryption_key_env` (optional) — name of an env var holding a base64
  32-byte AES-256 key. When set, every object is AES-256-GCM-sealed before
  upload (random nonce prefixed to the ciphertext), so the bucket only ever
  holds ciphertext — relevant for a "privacy-conscious team" story, since
  Google (or anyone with bucket read access but not the key) never sees
  plaintext transcripts. Omitting it uploads plaintext JSON.

Generate a key: `head -c32 /dev/urandom | base64`. Distribute it to the team
out of band (a password manager, `vault` bucket, Secret Manager, …) — this
prototype does not manage key distribution.

## Object layout

```
<prefix>/checkpoints/<shard>/<id>/sessions/<session>.json
<prefix>/checkpoints/<shard>/<id>/sessions/<session>.transcript.jsonl
<prefix>/checkpoints/<shard>/<id>/sessions/<session>.prompts.json
<prefix>/checkpoints/<shard>/<id>/summary.json
<prefix>/checkpoints/<shard>/<id>/tasks/<tool_use_id>.json
<prefix>/checkpoints/<shard>/<id>/tasks/<tool_use_id>.transcript.jsonl
```

`<shard>` is `id.ShardFor()` (the checkpoint ID's last two characters), the
same sharding the git-refs backend uses for `refs/entire/checkpoints/...` —
so a bucket browser fans out the same way the ref namespace does.

## What's deliberately out of scope for this prototype

- **Reads.** `Read`/`List`/`ListTasks`/`ReadTaskTranscript` all return a
  clear "mirror-only" error. The fan-out store never calls them (see
  `fanout.go`), so this is unreachable in practice; it exists so a future
  bug that *did* call them fails loudly instead of returning empty results
  that look like "no checkpoints."
- **Compaction/retention.** One object set per write; no lifecycle policy is
  set on the bucket. A real rollout wants a GCS lifecycle rule or a
  `gcs.prefix` per time window.
- **Key management.** A bare env var is fine for a prototype; production
  wants Secret Manager / KMS envelope encryption and key rotation.
- **Verified end-to-end test.** `e2e_demo_test.go`'s `TestManualEndToEndDemo`
  is a manual, opt-in (`ENTIRE_GCS_DEMO_REPO=...`) harness that exercises the
  real `checkpoint.Open` → mirror-build → `Write` path against the real GCS
  API (observed: a 404 against a bucket that doesn't exist, proving the
  client reaches Google and the primary write still succeeds). It is not run
  by `go test ./...` and is not a substitute for a CI test against a real or
  emulated bucket (e.g. `fake-gcs-server`).
