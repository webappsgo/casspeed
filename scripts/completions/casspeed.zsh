#compdef casspeed

_casspeed() {
    local -a opts
    opts=(
        '--help[Show help information]'
        '--version[Show version information]'
        '--mode[Application mode]:mode:(production development)'
        '--config[Configuration directory]:directory:_files -/'
        '--data[Data directory]:directory:_files -/'
        '--cache[Cache directory]:directory:_files -/'
        '--log[Log directory]:directory:_files -/'
        '--backup[Backup directory]:directory:_files -/'
        '--pid[PID file path]:file:_files'
        '--address[Listen address]:address:'
        '--port[Listen port]:port:'
        '--status[Show status and health]'
        '--service[Service management]:command:(start stop restart reload --install --uninstall --disable --help)'
        '--daemon[Daemonize (detach from terminal)]'
        '--debug[Enable debug mode]'
        '--maintenance[Maintenance operations]:operation:(backup restore update mode setup)'
        '--update[Update operations]:operation:(check yes branch)'
    )

    _arguments $opts
}

_casspeed "$@"
