# Command-line client

The `casspeed-cli` binary accepts a server URL and version/help flags.

```text
casspeed-cli --help
casspeed-cli --version
casspeed-cli --server https://speed.example.org
```

When started in an interactive terminal without a command, the client opens its terminal interface. The default server URL is `http://localhost:64580`. Result sharing and account automation use the same API privacy and authentication rules described in the [API guide](api.md).
