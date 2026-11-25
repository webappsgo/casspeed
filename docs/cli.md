# Command-line client

`casspeed-cli` runs a speed test from a terminal or script. In an interactive terminal, starting it without a command opens the TUI. In a non-interactive shell, it runs a speed test.

```sh
casspeed-cli --help
casspeed-cli --server https://speed.example.org test
casspeed-cli --server https://speed.example.org --output json test
casspeed-cli --server https://speed.example.org health
casspeed-cli --server https://speed.example.org --token-file ./token history
```

Commands are `test`, `health`, `history`, `share TEST_ID`, and `login`. The `login` command saves a supplied token to the per-user configuration directory with mode `0600`; token files with group or world permissions are rejected. Tokens can also be provided with `--token`, `--token-file`, or `CASSPEED_TOKEN`.

Unshared speed-test results remain private to the originating anonymous session or owning account. `share TEST_ID` explicitly creates a public share for an authenticated result. See the [API guide](api.md) for ownership and sharing behavior.
