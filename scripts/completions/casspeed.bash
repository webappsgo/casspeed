# Bash completion for casspeed

_casspeed() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--help --version --status --config --data --log --backup --service --maintenance --update"

    case "${prev}" in
        --config|--data|--log|--backup)
            COMPREPLY=( $(compgen -d -- ${cur}) )
            return 0
            ;;
        --service)
            COMPREPLY=( $(compgen -W "install start stop restart uninstall status" -- ${cur}) )
            return 0
            ;;
        --maintenance)
            COMPREPLY=( $(compgen -W "backup restore setup" -- ${cur}) )
            return 0
            ;;
        --update)
            COMPREPLY=( $(compgen -W "check yes branch" -- ${cur}) )
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _casspeed casspeed
