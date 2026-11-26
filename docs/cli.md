# Command-line client

`casspeed-cli` runs a speed test from a terminal or script. In an interactive terminal, starting it without a command opens the TUI. In a non-interactive shell, it runs a speed test.

```sh
casspeed-cli --help
casspeed-cli --server https://speed.example.org test
casspeed-cli --server https://speed.example.org --output json test
casspeed-cli --server https://speed.example.org health
casspeed-cli --server https://speed.example.org --token-file ./token history
casspeed-cli --server https://speed.example.org login YOUR_TOKEN
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
| `-h`, `--help` | — | Show usage and exit |
| `-v`, `--version` | — | Show build version and exit |

Starting without a command opens the TUI when run from an interactive terminal; in a non-interactive shell it runs `test`. The global options go before the command. `login TOKEN` is equivalent to `login --token TOKEN`; it saves the token for later commands. `history` and `share TEST_ID` need an authenticated user token.

Unshared speed-test results remain private to the originating anonymous session or owning account. `share TEST_ID` explicitly creates a public share for an authenticated result. See the [API guide](api.md) for ownership and sharing behavior.
