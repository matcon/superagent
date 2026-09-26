# superagent bash completion script
_superagent_completions() {
    local cur prev words cword
    _init_completion || return

    local subcommands="telemetry memory verify dag jit notify swe devsecops doctor version benchmark mcp"
    local mem_subcommands="add search graph"
    local swe_subcommands="audit guard plan spec fix sandbox"
    local devsecops_subcommands="audit container-check generate"
    local jit_subcommands="create list"
    local mcp_subcommands="serve"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return 0
    fi

    case "${words[1]}" in
        memory)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$mem_subcommands" -- "$cur") )
            fi
            ;;
        swe)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$swe_subcommands" -- "$cur") )
            elif [[ $cword -ge 3 ]]; then
                case "${words[2]}" in
                    audit|guard|fix)
                        COMPREPLY=( $(compgen -f -- "$cur") )
                        ;;
                    sandbox)
                        if [[ "$cur" == --* ]]; then
                            COMPREPLY=( $(compgen -W "--promote --message" -- "$cur") )
                        fi
                        ;;
                esac
            fi
            ;;
        devsecops)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$devsecops_subcommands" -- "$cur") )
            elif [[ $cword -eq 3 && "${words[2]}" == "generate" ]]; then
                COMPREPLY=( $(compgen -W "dockerfile k8s cicd" -- "$cur") )
            elif [[ $cword -ge 3 && "${words[2]}" == "container-check" ]]; then
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
        jit)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$jit_subcommands" -- "$cur") )
            fi
            ;;
        mcp)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$mcp_subcommands" -- "$cur") )
            fi
            ;;
        doctor|benchmark|telemetry)
            if [[ "$cur" == --* ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            fi
            ;;
        verify)
            if [[ "$cur" == --* ]]; then
                COMPREPLY=( $(compgen -W "--timeout --no-checkpoint" -- "$cur") )
            fi
            ;;
    esac
}

complete -F _superagent_completions superagent
