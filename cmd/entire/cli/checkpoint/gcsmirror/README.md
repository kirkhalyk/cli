# gcsmirror — GCS checkpoint mirror (prototype)

Fans out checkpoint writes to a Google Cloud Storage bucket, so a team can
share agent-session checkpoints through infrastructure they control instead
of (or alongside) Entire's own hosted service. No Entire account is needed:
auth is plain Google Application Default Credentials.

Registered as a **mirror-only, off-machine** backend
(`checkpoint.RegisterOffMachine`): it never serves reads and can never be the
primary. Git-refs (or git-branch) stays the source of truth; this backend
gets a best-effort copy of every write.

Failures never break `entire`:

- A mirror that cannot be constructed (key env var missing or malformed) is
  skipped with a warning by `checkpoint.buildMirrors`; `checkpoint.Open` and
  the primary are unaffected.
- Google credentials are resolved lazily on the first write, not in the
  factory, so read-only commands (`explain`, `status`, `resume`) never pay a
  credential lookup or metadata-server probe.
- A write failure (no credentials, unreachable bucket, 4xx/5xx) is logged and
  swallowed by `fanoutStore.Write`. Each `Write` shares one 15 s budget across
  all its uploads (10 s per request), so a dead network costs a commit seconds,
  not minutes.

## Wiring it into a build

```go
import "github.com/entireio/cli/cmd/entire/cli/checkpoint/gcsmirror"

func main() {
    gcsmirror.Register() // before any checkpoint.Open call
    ...
}
```

(Done in this prototype's `cmd/entire/main.go`.)

## Configuration

**Only from developer-owned config.** Because this backend uploads with your
own Google credentials, the mirror entry is honored only from an *untracked*
`.entire/settings.local.json` (verified absent from both the index and `HEAD`)
or the `ENTIRE_CHECKPOINTS_*` env override. A `gcs` mirror in the
version-controlled `.entire/settings.json` is skipped with a warning —
otherwise one line in a pull request could send every teammate's checkpoints
to a bucket of its author's choosing.

`.entire/settings.local.json`:

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
  upload (format below), so the bucket only ever holds ciphertext — relevant for a "privacy-conscious team" story, since
  Google (or anyone with bucket read access but not the key) never sees
  plaintext transcripts. Omitting it uploads plaintext JSON.

Generate a key: `head -c32 /dev/urandom | base64`. Distribute it to the team
out of band (a password manager, `vault` bucket, Secret Manager, …) — this
prototype does not manage key distribution.

## Redaction

The mirror redacts exactly what the git writer and `fsstore` redact:
prompts (`RedactedJoinedPrompts`), the summary (`RedactSummary`), task
descriptions, review prompts and investigate topics (`redact.String`).
Transcripts arrive pre-redacted (`redact.RedactedBytes`) and get the same
sanitize safety net; the `TranscriptPath` fallback goes through
`checkpoint.ReadRedactedTranscriptFile` (sanitize → image drop → redact). The
mirror does **not** receive the pre-push OPF re-redaction or cleanup deletes
(see `fanout.go`), so it can hold content the primary later rewrites.

## Encrypted object format (v1)

```
version (1 byte, 0x01) || key ID (8 bytes) || nonce (12 bytes) || AES-GCM ciphertext+tag
```

- key ID = first 8 bytes of SHA-256(key), so a reader holding several keys
  across a rotation can pick the right one.
- Associated data = the 9-byte header followed by the full object name, so a
  ciphertext only decrypts under the name it was written to; copying one
  session's object over another's fails authentication.

## Object layout

```
<prefix>/checkpoints/<shard>/<id>/sessions/<session>.json
<prefix>/checkpoints/<shard>/<id>/sessions/<session>.transcript.jsonl
<prefix>/checkpoints/<shard>/<id>/sessions/<session>.prompts.txt
<prefix>/checkpoints/<shard>/<id>/summary.json
<prefix>/checkpoints/<shard>/<id>/tasks/<tool_use_id>.json
<prefix>/checkpoints/<shard>/<id>/tasks/<tool_use_id>.transcript.jsonl
```

`<shard>` is `id.ShardFor()` (the checkpoint ID's last two characters), the
same sharding the git-refs backend uses for `refs/entire/checkpoints/...` —
so a bucket browser fans out the same way the ref namespace does. Session and
tool-use IDs are validated (`validation.ValidateSessionID` /
`ValidateToolUseID`) before they become object-name segments, so a `../` in
one cannot write outside the checkpoint's prefix.

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
  wants Secret Manager / KMS envelope encryption. Objects carry a key ID, but
  nothing re-encrypts old objects on rotation.
- **Async upload.** Uploads are synchronous on the commit path, bounded by the
  per-`Write` budget. An offline queue would remove even that cost.
- **Verified end-to-end test.** `e2e_demo_test.go`'s `TestManualEndToEndDemo`
  is a manual harness behind the `manual` build tag
  (`go test -tags manual ./cmd/entire/cli/checkpoint/gcsmirror -run TestManualEndToEndDemo -v`) that exercises the
  real `checkpoint.Open` → mirror-build → `Write` path against the real GCS
  API (observed: a 404 against a bucket that doesn't exist, proving the
  client reaches Google and the primary write still succeeds). It is not built
  by `go test ./...` (it reads your real Application Default Credentials) and is not a substitute for a CI test against a real or
  emulated bucket (e.g. `fake-gcs-server`).
