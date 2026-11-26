# Command-line client

`casspeed-cli` runs a speed test from a terminal or script. In an interactive terminal, starting it without a command opens the TUI. In a non-interactive shell, it runs a speed test.

```sh
casspeed-cli --help
casspeed-cli --server https://speed.example.org test
casspeed-cli --server https://speed.example.org --output json test
casspeed-cli --server https://speed.example.org health
casspeed-cli --server https://speed.example.org --token-file ./token history
casspeed-cli --server https://speed.example.org login YOUR_TOKEN
casspeed-cli --server https://speed.example.org --update check
casspeed-cli --server https://speed.example.org --update yes
```

Commands are `test`, `health`, `history`, `share TEST_ID`, and `login [TOKEN]`. The `login` command saves a supplied token to the per-user configuration directory with mode `0600`; token files with group or world permissions are rejected. Token lookup order is `--token`, `--token-file`, `CASSPEED_TOKEN`, then the saved per-user token. Supported interface languages are `en`, `es`, `fr`, `de`, `it`, and `ar`; select one with `--lang CODE`.

## Options

| Option | Default | Description |
|---|---|---|
| `--server URL` | `http://localhost:64580` | Server base URL; it must be an absolute HTTP or HTTPS URL |
| `--lang CODE` | Automatic | Output and request language; otherwise the client uses `LC_ALL`, then `LANG` |
| `--token TOKEN` | None | API bearer token |
| `--token-file FILE` | None | Read the bearer token from a permission-restricted file |
| `--output FORMAT` | `table` | Select `table` or `json` output |
| `--update ACTION` | Automatic check | `check` reports the available release; `yes` requests an update |
| `-h`, `--help` | — | Show usage and exit |
| `-v`, `--version` | — | Show build version and exit |

Starting without a command opens the TUI when run from an interactive terminal; in a non-interactive shell it runs `test`. The global options go before the command. `login TOKEN` is equivalent to `login --token TOKEN`; it saves the token for later commands. `history` and `share TEST_ID` need an authenticated user token.

Unshared speed-test results remain private to the originating anonymous session or owning account. `share TEST_ID` explicitly creates a public share for an authenticated result. See the [API guide](api.md) for ownership and sharing behavior.

## Updating the CLI

The CLI checks `/api/autodiscover` on each invocation. `--update check` reports the release for the current operating system and architecture without installing it. When an update is available in an interactive terminal, the CLI asks before installing it. In a non-interactive shell, installation requires both `--update yes` and `update.auto: true` in `cli.yml`; otherwise the command continues without changing the binary.

Updates are downloaded from the configured server over HTTPS (HTTP is accepted only for loopback development servers), optionally with the saved bearer token. The CLI verifies the downloaded file against the server's published SHA-256 checksum and stages it in a private project-scoped temporary directory. It atomically replaces the installed binary on Unix systems and uses a Windows sidecar swap on Windows, then starts the new version with the original arguments. If the install location is not writable, move the binary to a writable location or ask an administrator to update it. On Windows, the running binary is renamed to a `.old` sidecar and scheduled for removal at reboot before the new version is started.

The `update.auto` setting defaults to `false`:

```yaml
update:
  auto: false
  check_interval: per_invocation
  channel: stable
```

The default configuration file is `~/.config/casapps/casspeed/cli.yml`. If the server's `cli_min_version` is newer than the running CLI, ordinary commands stop until a compatible release is installed; use `--update yes` or ask the operator to publish a release meeting the required minimum.
