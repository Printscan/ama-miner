#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/h-manifest.conf"

LOG_FILE="${CUSTOM_LOG_BASENAME}.log"
VERSION_VALUE="${CUSTOM_VERSION:-}"
ALGO_VALUE="${CUSTOM_ALGO:-}"
GPU_STATS_FILE=/run/hive/gpu-stats.json

json_escape() {
  local str=${1-}
  str=${str//\/\\}
  str=${str//"/\\"}
  str=${str//$'\n'/\\n}
  str=${str//$'\r'/\\r}
  str=${str//$'\t'/\\t}
  echo "$str"
}

array_to_json_numbers() {
  local -n arr_ref=$1
  local default=${2:-0}
  local output="["
  local val
  for val in "${arr_ref[@]}"; do
    [[ -z $val ]] && val=$default
    output+="${val},"
  done
  if [[ $output == "[" ]]; then
    printf '[]'
  else
    printf '%s' "${output%,}]"
  fi
}

declare -a temp_arr fan_arr busids_hex bus_arr
if command -v jq >/dev/null 2>&1 && [[ -f $GPU_STATS_FILE ]]; then
  mapfile -t temp_arr   < <(jq -r '.temp[]? | tonumber' "$GPU_STATS_FILE")
  mapfile -t fan_arr    < <(jq -r '.fan[]? | tonumber' "$GPU_STATS_FILE")
  mapfile -t busids_hex < <(jq -r '.busids[]?' "$GPU_STATS_FILE")
fi

for id in "${busids_hex[@]}"; do
  bus_part=${id%%:*}
  if [[ $bus_part =~ ^[0-9a-fA-F]+$ ]]; then
    bus_arr+=( $((16#$bus_part)) )
  else
    bus_arr+=(0)
  fi
done

declare -A seen_idx hs_map
if [[ -f $LOG_FILE ]]; then
  while IFS= read -r line; do
    if [[ $line =~ Hashrate[[:space:]]GPU[[:space:]]\#([0-9]+)[[:space:]]=[[:space:]]([0-9.]+) ]]; then
      idx=${BASH_REMATCH[1]}
      if [[ -z ${seen_idx[$idx]:-} ]]; then
        seen_idx[$idx]=1
        hs_map[$idx]=${BASH_REMATCH[2]}
      fi
    fi
  done < <(tac "$LOG_FILE" | head -n 2000)
fi

gpu_count=0
(( ${#temp_arr[@]} > gpu_count )) && gpu_count=${#temp_arr[@]}
(( ${#fan_arr[@]}  > gpu_count )) && gpu_count=${#fan_arr[@]}
(( ${#bus_arr[@]}  > gpu_count )) && gpu_count=${#bus_arr[@]}
for idx in "${!hs_map[@]}"; do
  (( idx + 1 > gpu_count )) && gpu_count=$(( idx + 1 ))
done

declare -a hs_arr temp_out fan_out bus_out
have_temp=false
have_fan=false
have_bus=false

(( ${#temp_arr[@]} > 0 )) && have_temp=true
(( ${#fan_arr[@]}  > 0 )) && have_fan=true
(( ${#bus_arr[@]}  > 0 )) && have_bus=true

for ((i=0; i<gpu_count; i++)); do
  raw=${hs_map[$i]:-0}
  if [[ $raw == 0 ]]; then
    kh=0
  else
    kh=$(awk -v v="$raw" 'BEGIN { printf "%.3f", v/1000 }')
  fi
  hs_arr[i]=$kh
  if $have_temp; then
    temp_out[i]=${temp_arr[i]:-0}
  fi
  if $have_fan; then
    fan_out[i]=${fan_arr[i]:-0}
  fi
  if $have_bus; then
    bus_out[i]=${bus_arr[i]:-0}
  fi
done

if ! $have_temp; then
  temp_out=()
fi
if ! $have_fan; then
  fan_out=()
fi
if ! $have_bus; then
  bus_out=()
fi

if ((${#hs_arr[@]} > 0)); then
  sum_khs=$(printf '%s\n' "${hs_arr[@]}" | awk 'BEGIN { s = 0 } NF { s += $1 } END { if (NR == 0) printf "0"; else printf "%.3f", s }')
else
  sum_khs=0
fi

if [[ -f $LOG_FILE ]]; then
  now=$(date +%s)
  file_mtime=$(stat -c %Y "$LOG_FILE" 2>/dev/null || echo 0)
  (( uptime = now - file_mtime ))
  (( uptime < 0 )) && uptime=0
else
  uptime=0
fi

hs_json=$(array_to_json_numbers hs_arr 0)
temp_json=$(array_to_json_numbers temp_out 0)
fan_json=$(array_to_json_numbers fan_out 0)
bus_json=$(array_to_json_numbers bus_out 0)

if command -v jq >/dev/null 2>&1; then
  stats=$(jq -nc \
    --argjson hs "$hs_json" \
    --argjson temp "$temp_json" \
    --argjson fan "$fan_json" \
    --argjson uptime "$uptime" \
    --arg ver "$VERSION_VALUE" \
    --arg algo "$ALGO_VALUE" \
    --argjson bus "$bus_json" \
    --arg total "$sum_khs" \
    '{
      hs: $hs,
      hs_units: "khs",
      temp: $temp,
      fan: $fan,
      uptime: $uptime,
      ver: $ver,
      ar: [0, 0],
      bus_numbers: $bus,
      total_khs: ($total | tonumber)
    } | if $algo == "" then . else . + {algo: $algo} end'
  )
else
  ver_json=$(json_escape "$VERSION_VALUE")
  stats="{\"hs\":$hs_json,\"hs_units\":\"khs\",\"temp\":$temp_json,\"fan\":$fan_json,\"uptime\":$uptime,\"ver\":\"$ver_json\",\"ar\":[0,0],\"bus_numbers\":$bus_json,\"total_khs\":$sum_khs"
  if [[ -n $ALGO_VALUE ]]; then
    algo_json=$(json_escape "$ALGO_VALUE")
    stats+=",\"algo\":\"$algo_json\"}"
  else
    stats+='}'
  fi
fi

[[ -z $sum_khs ]] && sum_khs=0
[[ -z $stats ]] && stats='{"hs":[],"hs_units":"khs","temp":[],"fan":[],"uptime":0,"ver":"","ar":[0,0],"total_khs":0}'

echo "$sum_khs"
echo "$stats"
