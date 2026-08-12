#!/bin/sh

# Shared process inspection for the Codex Orient hooks. This file is sourced by
# the event scripts; invoking it directly intentionally does nothing.

# Print "persona<TAB>pile" for an Orient wait command. Process listings do not
# preserve shell quoting, so persona labels and pile paths containing whitespace
# cannot be reconstructed reliably and deliberately do not match.
orient_parse_wait_command() {
    printf '%s\n' "$1" | awk '
      {
        first = 1
        while (first <= NF && $first == "") first++
        command = ""
        persona = ""
        pile = ""
        for (i = first + 1; i <= NF; i++) {
          token = $i
          if (token == "--persona") {
            if (++i > NF) exit 1
            persona = $i
          } else if (index(token, "--persona=") == 1) {
            persona = substr(token, length("--persona=") + 1)
          } else if (token == "--pile") {
            if (++i > NF) exit 1
            pile = $i
          } else if (index(token, "--pile=") == 1) {
            pile = substr(token, length("--pile=") + 1)
          } else if (token == "--key") {
            if (++i > NF) exit 1
          } else if (index(token, "--key=") == 1 || token ~ /^-/) {
            continue
          } else if (command == "") {
            command = token
          }
        }

        if (command != "wait") exit 1
        printf "%s\t%s\n", persona, pile
      }
    '
}

orient_process_env_value() {
    orient_env_pid=$1
    orient_env_name=$2
    orient_process_env "$orient_env_pid" | awk -v name="$orient_env_name" '
      {
        prefix = name "="
        if (index($0, prefix) == 1) value = substr($0, length(prefix) + 1)
      }
      END { if (value != "") print value }
    '
}

orient_process_env() {
    orient_env_pid=$1
    if [ -r "/proc/$orient_env_pid/environ" ]; then
        tr '\000' '\n' < "/proc/$orient_env_pid/environ" 2>/dev/null
        return 0
    fi
    ps eww -p "$orient_env_pid" -o command= 2>/dev/null | tr ' ' '\n'
}

orient_process_cwd() {
    orient_cwd_pid=$1

    if [ -e "/proc/$orient_cwd_pid/cwd" ]; then
        readlink "/proc/$orient_cwd_pid/cwd" 2>/dev/null && return 0
    fi

    if command -v lsof >/dev/null 2>&1; then
        orient_cwd=$(
            lsof -a -p "$orient_cwd_pid" -d cwd -Fn 2>/dev/null |
                sed -n 's/^n//p' | sed -n '1p'
        )
        if [ -n "$orient_cwd" ]; then
            printf '%s\n' "$orient_cwd"
            return 0
        fi
    fi

    orient_process_env_value "$orient_cwd_pid" PWD
}

orient_canonical_path() {
    orient_path=$1
    orient_cwd=${2:-}
    case "$orient_path" in
        /*) ;;
        *)
            [ -n "$orient_cwd" ] || return 1
            orient_path=$orient_cwd/$orient_path
            ;;
    esac

    if command -v realpath >/dev/null 2>&1; then
        orient_realpath=$(realpath "$orient_path" 2>/dev/null || true)
        if [ -n "$orient_realpath" ]; then
            printf '%s\n' "$orient_realpath"
            return 0
        fi
    fi

    orient_dir=${orient_path%/*}
    orient_name=${orient_path##*/}
    orient_dir=$(CDPATH= cd -P "$orient_dir" 2>/dev/null && pwd -P) || return 1
    printf '%s/%s\n' "$orient_dir" "$orient_name"
}

# Print exact PIDs for live processes that are semantically the configured
# watcher. Flags may appear in either order and in --flag=value or
# --flag value form. PILE/PERSONA are consulted when the corresponding CLI
# flag is absent. Relative pile paths are resolved against the process cwd.
orient_watcher_pids() {
    orient_match_pile=$1
    orient_match_persona=$2
    orient_expected_pile=$(orient_canonical_path "$orient_match_pile" "$(pwd -P)") || return 0
    orient_expected_persona=$orient_match_persona
    orient_tab=$(printf '\t')

    # Linux truncates `comm` to 15 bytes, so an explicitly renamed executable
    # may not be discoverable via `pgrep -x`. `ps -A` lets the parser validate
    # the argv shape without relying on that field. A configured executable
    # that was launched through another spelling (relative path or symlink) is
    # still accepted; exact persona + canonical pile + wait subcommand are the
    # semantic identity, and commands wrapped inside a shell are rejected.
    while IFS= read -r orient_line; do
        orient_pid=${orient_line%% *}
        orient_command=${orient_line#* }
        [ "$orient_command" != "$orient_line" ] || continue
        orient_command=$(
            ps -ww -p "$orient_pid" -o command= 2>/dev/null |
                sed 's/^[[:space:]]*//' || true
        )
        [ -n "$orient_command" ] || continue
        orient_executable=${orient_command%% *}
        orient_executable_name=${orient_executable##*/}
        [ "$orient_executable_name" = orient ] || continue
        orient_fields=$(orient_parse_wait_command "$orient_command" 2>/dev/null) || continue
        orient_persona=${orient_fields%%"$orient_tab"*}
        orient_pile=${orient_fields#*"$orient_tab"}

        if [ -z "$orient_persona" ]; then
            orient_persona=$(orient_process_env_value "$orient_pid" PERSONA)
        fi
        [ -n "$orient_persona" ] || continue
        case "$orient_persona" in *[![:graph:]]*) continue ;; esac
        [ "$orient_persona" = "$orient_expected_persona" ] || continue

        if [ -z "$orient_pile" ]; then
            orient_pile=$(orient_process_env_value "$orient_pid" PILE)
        fi
        [ -n "$orient_pile" ] || continue
        case "$orient_pile" in *[![:graph:]]*) continue ;; esac
        orient_cwd=$(orient_process_cwd "$orient_pid" 2>/dev/null || true)
        orient_actual_pile=$(orient_canonical_path "$orient_pile" "$orient_cwd" 2>/dev/null || true)
        [ -n "$orient_actual_pile" ] || continue
        [ "$orient_actual_pile" = "$orient_expected_pile" ] || continue

        printf '%s\n' "$orient_pid"
    done <<EOF
$(ps -ww -A -o pid=,command= 2>/dev/null | sed 's/^[[:space:]]*//')
EOF
}

# A direct child of init has lost the harness process that owned its output.
# Anything less certain is preserved: another live Codex window may
# intentionally own the configured watcher, and killing it would lose news.
orient_watcher_is_stale() {
    orient_stale_pid=$1
    orient_stale_state=$(ps -p "$orient_stale_pid" -o stat= 2>/dev/null | awk '{print $1}')
    [ -n "$orient_stale_state" ] || return 0
    case "$orient_stale_state" in
        Z*) return 0 ;;
    esac
    orient_stale_ppid=$(ps -p "$orient_stale_pid" -o ppid= 2>/dev/null | awk '{print $1}')
    [ "$orient_stale_ppid" = 1 ]
}

orient_live_watcher_pids() {
    orient_live_pile=$1
    orient_live_persona=$2
    for orient_live_pid in $(orient_watcher_pids "$orient_live_pile" "$orient_live_persona"); do
        if ! orient_watcher_is_stale "$orient_live_pid"; then
            printf '%s\n' "$orient_live_pid"
        fi
    done
}
