#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/h-manifest.conf"

BIN_PATH="$SCRIPT_DIR/ama-miner"
CONFIG_FILE="$CUSTOM_CONFIG_FILENAME"
LOG_FILE="${CUSTOM_LOG_BASENAME}.log"

[[ -x "$BIN_PATH" ]] || chmod +x "$BIN_PATH"
[[ -f "$CONFIG_FILE" ]] || {
  echo "ERROR: config file not found: $CONFIG_FILE" >&2
  exit 1
}

source "$CONFIG_FILE"

host="${HOST:-}"
user="${USER:-}"
pass="${PASS:-}"
extra_args="${EXTRA_ARGS:-}"

nvtool_opts=()
nvtool_vals=()
miner_extra_args=()

add_nvtool_cmd() {
  local opt="$1"
  local value="$2"

  if [[ -z $value ]]; then
    echo "WARNING: $opt requires a numeric value" >&2
    return
  fi

  if [[ ! $value =~ ^-?[0-9]+$ ]]; then
    echo "WARNING: ignoring $opt with non-numeric value '$value'" >&2
    return
  fi

  nvtool_opts+=("$opt")
  nvtool_vals+=("$value")
}

if [[ -n "$extra_args" ]]; then
  eval "set -- $extra_args"
  while (($#)); do
    token=$1
    shift

    case $token in
      nvtool)
        if (($# == 0)); then
          miner_extra_args+=("nvtool")
          break
        fi
        opt=$1
        shift

        if [[ $opt == --setcore=* || $opt == --setmem=* || $opt == --setmemoffset=* || $opt == --setcoreoffset=* || $opt == --setclocks=* || $opt == --setpl=* ]]; then
          value=${opt#*=}
          opt=${opt%%=*}
          add_nvtool_cmd "$opt" "$value"
          continue
        fi

        case $opt in
          --setcore|--setmem|--setmemoffset|--setcoreoffset|--setclocks|--setpl)
            if (($# == 0)); then
              echo "WARNING: $opt requires a numeric value" >&2
              continue
            fi
            value=$1
            shift
            add_nvtool_cmd "$opt" "$value"
            continue
            ;;
          *)
            miner_extra_args+=("nvtool" "$opt")
            continue
            ;;
        esac
        ;;
      --setcore|--setmem|--setmemoffset|--setcoreoffset|--setclocks|--setpl)
        if (($# == 0)); then
          echo "WARNING: $token requires a numeric value" >&2
          continue
        fi
        value=$1
        shift
        add_nvtool_cmd "$token" "$value"
        continue
        ;;
      --setcore=*|--setmem=*|--setmemoffset=*|--setcoreoffset=*|--setclocks=*|--setpl=*)
        opt=${token%%=*}
        value=${token#*=}
        add_nvtool_cmd "$opt" "$value"
        continue
        ;;
      *)
        miner_extra_args+=("$token")
        ;;
    esac
  done
fi

if ((${#nvtool_opts[@]})); then
  if command -v nvtool >/dev/null 2>&1; then
    for idx in "${!nvtool_opts[@]}"; do
      opt="${nvtool_opts[$idx]}"
      value="${nvtool_vals[$idx]}"
      echo "Applying nvtool $opt $value"
      if ! nvtool "$opt" "$value"; then
        echo "WARNING: command failed: nvtool $opt $value" >&2
      fi
    done
  else
    echo "WARNING: nvtool not found in PATH, skipping clock adjustments" >&2
  fi
fi

if [[ -z "$host" ]]; then
  if [[ -z "$extra_args" || ! "$extra_args" =~ (--host) ]]; then
    echo "ERROR: Pool host is not configured. Check your flight sheet." >&2
    exit 1
  fi
fi
if [[ -z "$user" ]]; then
  if [[ -z "$extra_args" || ! "$extra_args" =~ (--user) ]]; then
    echo "ERROR: Miner user/wallet is not configured. Check your flight sheet." >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

cmd=("$BIN_PATH")
[[ -n "$host" ]] && cmd+=(--host "$host")
[[ -n "$user" ]] && cmd+=(--user "$user")
[[ -n "$pass" ]] && cmd+=(--pass "$pass")

if ((${#miner_extra_args[@]})); then
  for extra_arg in "${miner_extra_args[@]}"; do
    cmd+=("$extra_arg")
  done
fi

printf 'Starting %s with command:' "$CUSTOM_NAME"
for arg in "${cmd[@]}"; do
  printf ' %q' "$arg"
done
printf '\n'

set +e
"${cmd[@]}" 2>&1 | tee -a "$LOG_FILE"
exit_code=${PIPESTATUS[0]}
set -e

exit $exit_code
