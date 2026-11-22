# tuf-sign

TUF (The Update Framework) signing and publishing tooling for the
[unistack](https://github.com/unistack-org/unistack) cell update framework.

This repo holds two things, extracted from the main `unistack` repo so the
cell's CI can download a prebuilt binary instead of building it:

- **`pkg/tuf`** — the TUF library (metadata types, canonical JSON, signing,
  chain verification, channel/mirror helpers). Pure Go stdlib, no external
  dependencies.
- **`cmd/tuf-sign`** — the CI signing CLI (`genkey`, `init-root`, `publish`,
  `promote`, `resign`, `verify`).

## Why a separate repo

The `unistack` repo's `tuf-publish` / `tuf-promote` / `tuf-timestamp` jobs
used to `go build ./cmd/tuf-sign` in place, which forced a full Go toolchain
setup in those jobs. The tool is now built here and published as a GitHub
release asset; the main repo downloads the prebuilt binary, so those jobs no
longer need Go at all.

## Usage

```sh
# install
go install github.com/unistack-org/tuf-sign/cmd/tuf-sign@latest

# or download a prebuilt release binary
# https://github.com/unistack-org/tuf-sign/releases
```

Subcommands:

| command     | purpose                                                        |
| ----------- | -------------------------------------------------------------- |
| `genkey`    | generate an ed25519 key file (hex seed)                        |
| `init-root` | build `root.json` + top-level `targets.json` (offline, rare)   |
| `publish`   | add a release binary to a channel, re-pin snapshot+timestamp   |
| `promote`   | re-sign an existing target into a more senior channel          |
| `resign`    | re-sign timestamp (and snapshot near expiry) — cron job        |
| `verify`    | full TUF chain check of the state dir + artefact hashes        |

Root keys never enter CI: `root.json` is signed offline by `init-root` and
deployed as a static file. CI holds only the online keys (timestamp,
snapshot, the channel being published) as secrets rendered to files.

## Development

```sh
go test ./...
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
