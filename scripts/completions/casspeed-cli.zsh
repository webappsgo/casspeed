#compdef casspeed-cli

_casspeed_cli() {
    local -a opts
    opts=(
        '--help[Show help information]'
        '--version[Show version information]'
        '--server[Server URL]:url:'
        '--token[API token]:token:'
        '--output[Output format]:format:(text json table)'
        '--debug[Enable debug output]'
        'test[Run speed test]'
        'history[Show test history]'
        'export[Export test data]'
    )

    _arguments $opts
}

_casspeed_cli "$@"
