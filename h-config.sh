#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/h-manifest.conf"

error() {
  echo "ERROR: $*" >&2
  return 1
}

[[ -z "${CUSTOM_CONFIG_FILENAME:-}" ]] && error "CUSTOM_CONFIG_FILENAME is not set"
[[ -z "${CUSTOM_TEMPLATE:-}" ]] && error "CUSTOM_TEMPLATE (wallet/user) is empty"
[[ -z "${CUSTOM_URL:-}" ]] && error "CUSTOM_URL (pool URL) is empty"

substitute_placeholders() {
  local value="$1"
  value="${value//%WORKER_NAME%/${WORKER_NAME:-}}"
  value="${value//%WORKER_ID%/${WORKER_ID:-}}"
  value="${value//%FARM_ID%/${FARM_ID:-}}"
  echo "$value"
}

user=$(substitute_placeholders "$CUSTOM_TEMPLATE")
pass_template="${CUSTOM_PASS:-%WORKER_NAME%}"
pass=$(substitute_placeholders "$pass_template")
if [[ -z "$pass" ]]; then
  pass="${WORKER_NAME:-}"
fi

# Split CUSTOM_URL by comma or newline and take the first non-empty entry
mapfile -t pool_list < <(printf '%s\n' "$CUSTOM_URL" |
  tr ',' '\n' |
  sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
  sed '/^$/d')

primary_pool="${pool_list[0]:-}"
[[ -z "$primary_pool" ]] && error "Unable to parse pool address from CUSTOM_URL"

# Drop known schemes if present (stratum+tcp://, ssl://, etc.)
primary_pool="${primary_pool#stratum+tcp://}"
primary_pool="${primary_pool#stratum+ssl://}"
primary_pool="${primary_pool#stratum+tls://}"
primary_pool="${primary_pool#ssl://}"
primary_pool="${primary_pool#tcp://}"
primary_pool="${primary_pool#http://}"
primary_pool="${primary_pool#https://}"

extra_args="${CUSTOM_USER_CONFIG:-}"

if [[ -n "$extra_args" ]]; then
  if [[ "$extra_args" =~ (^|[[:space:]])--host([=[:space:]]|$) ]]; then
    primary_pool=""
  fi
  if [[ "$extra_args" =~ (^|[[:space:]])--user([=[:space:]]|$) ]]; then
    user=""
  fi
  if [[ "$extra_args" =~ (^|[[:space:]])--pass([=[:space:]]|$) ]]; then
    pass=""
  fi
fi

mkdir -p "$(dirname "$CUSTOM_CONFIG_FILENAME")"
cat > "$CUSTOM_CONFIG_FILENAME" <<CFG
HOST=$(printf '%q' "$primary_pool")
USER=$(printf '%q' "$user")
PASS=$(printf '%q' "$pass")
EXTRA_ARGS=$(printf '%q' "$extra_args")
CFG

chmod 600 "$CUSTOM_CONFIG_FILENAME"
