#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/h-manifest.conf"

LOG_FILE="${CUSTOM_LOG_BASENAME}.log"
VERSION_VALUE="${CUSTOM_VERSION:-}"
ALGO_VALUE="${CUSTOM_ALGO:-}"
BIN_PATH="$SCRIPT_DIR/ama-miner"
IGNORE_PCI_BUS_00=${IGNORE_PCI_BUS_00:-1}
LAST_STATS_FILE=/run/hive/last_stat.json
SHARE_STATE_FILE=/run/hive/amaminer_share.state

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

should_skip_bus_id() {
  local id=${1,,}
  if [[ $id =~ ^([0-9a-f]{4}|[0-9a-f]{8}):([0-9a-f]{2}):([0-9a-f]{2})\.([0-7])$ ]]; then
    local bus=${BASH_REMATCH[2]}
    local func=${BASH_REMATCH[4]}
    if [[ $bus == "00" ]] && [[ $func == "0" ]]; then
      return 0
    fi
  elif [[ $id =~ ^([0-9a-f]{2}):([0-9a-f]{1,2})\.([0-7])$ ]]; then
    local bus=${BASH_REMATCH[1]}
    local func=${BASH_REMATCH[3]}
    if [[ $bus == "00" ]] && [[ $func == "0" ]]; then
      return 0
    fi
  fi
  return 1
}

get_proc_uptime() {
  if [[ ! -x $BIN_PATH ]]; then
    return 1
  fi
  if ! command -v pgrep >/dev/null 2>&1; then
    return 1
  fi

  mapfile -t pids < <(pgrep -f "$BIN_PATH" 2>/dev/null || true)
  for pid in "${pids[@]}"; do
    [[ -z $pid ]] && continue
    etimes=$(ps -p "$pid" -o etimes= 2>/dev/null | awk 'NR==1 { gsub(/^[ \t]+/, ""); print }')
    if [[ $etimes =~ ^[0-9]+$ ]]; then
      echo "$etimes"
      return 0
    fi
  done

  return 1
}

get_previous_accepted() {
  local prev=0
  if [[ -f $LAST_STATS_FILE ]]; then
    if command -v jq >/dev/null 2>&1; then
      prev=$(jq -r 'try .params.miner_stats.ar[0] catch 0' "$LAST_STATS_FILE" 2>/dev/null || echo 0)
    elif command -v python3 >/dev/null 2>&1; then
      prev=$(python3 - "$LAST_STATS_FILE" <<'PY'
import json, sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as fh:
        data = json.load(fh)
    val = data.get('params', {}).get('miner_stats', {}).get('ar', [0, 0])
    if isinstance(val, (list, tuple)) and val:
        v = val[0]
        if isinstance(v, (int, float)):
            print(int(v))
        else:
            print(0)
    else:
        print(0)
except Exception:
    print(0)
PY
      )
    else
      prev=$(grep -o '"ar"\s*:\s*\[[0-9]\+' "$LAST_STATS_FILE" 2>/dev/null | head -n1 | grep -o '[0-9]\+' || printf '0')
    fi
  fi
  [[ $prev =~ ^[0-9]+$ ]] || prev=0
  echo "$prev"
}

declare -a temp_arr fan_arr busids_hex bus_arr
temp_arr=()
fan_arr=()
busids_hex=()
bus_arr=()
declare -A skip_idx

if command -v nvidia-smi >/dev/null 2>&1; then
  while IFS=, read -r idx temp fan busid; do
    idx=${idx//[[:space:]]/}
    [[ -z $idx ]] && continue

    temp=${temp//[[:space:]]/}
    if [[ ! $temp =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
      temp=0
    fi
    temp=${temp%%.*}

    fan=${fan//[[:space:]]/}
    if [[ ! $fan =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
      fan=0
    fi
    fan=${fan%%.*}

    busid=${busid//[[:space:]]/}
    [[ -z $busid ]] && busid="0000:00:00.0"

    temp_arr[idx]=$temp
    fan_arr[idx]=$fan
    busids_hex[idx]=${busid,,}
  done < <(nvidia-smi --query-gpu=index,temperature.gpu,fan.speed,pci.bus_id --format=csv,noheader,nounits 2>/dev/null || true)
fi

all_bus_zero=true
for idx in "${!busids_hex[@]}"; do
  id=${busids_hex[idx]}
  if (( IGNORE_PCI_BUS_00 != 0 )) && should_skip_bus_id "$id"; then
    skip_idx[$idx]=1
  fi
  bus_part=${id%%:*}
  if [[ $id =~ ^([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.[0-7]$ ]]; then
    bus_part=${BASH_REMATCH[2]}
  elif [[ $id =~ ^([0-9a-fA-F]{2}):([0-9a-fA-F]{1,2})\.[0-7]$ ]]; then
    bus_part=${BASH_REMATCH[1]}
  fi
  if [[ $bus_part =~ ^[0-9a-fA-F]+$ ]]; then
    bus_arr[$idx]=$((16#$bus_part))
    if (( bus_arr[$idx] != 0 )); then
      all_bus_zero=false
    fi
  else
    bus_arr[$idx]=0
  fi
done

if $all_bus_zero; then
  skip_idx=()
fi

share_prev_inode=0
share_prev_count=0
share_prev_total=0
if [[ -f $SHARE_STATE_FILE ]]; then
  read -r share_prev_inode share_prev_count share_prev_total < "$SHARE_STATE_FILE" || true
fi
[[ $share_prev_inode =~ ^[0-9]+$ ]] || share_prev_inode=0
[[ $share_prev_count =~ ^[0-9]+$ ]] || share_prev_count=0
[[ $share_prev_total =~ ^[0-9]+$ ]] || share_prev_total=0

log_inode=0
if [[ -f $LOG_FILE ]]; then
  log_inode=$(stat -c %i "$LOG_FILE" 2>/dev/null || echo 0)
fi
[[ $log_inode =~ ^[0-9]+$ ]] || log_inode=0

share_count_current=0
if [[ -f $LOG_FILE ]]; then
  if command -v rg >/dev/null 2>&1; then
    share_count_current=$(rg --count --no-filename --fixed-strings 'Solution accepted!' "$LOG_FILE" 2>/dev/null || printf '0')
  else
    share_count_current=$(grep -c 'Solution accepted!' "$LOG_FILE" 2>/dev/null || printf '0')
  fi
fi
share_count_current=${share_count_current//$'\r'/}
share_count_current=${share_count_current//$'\n'/}
[[ $share_count_current =~ ^[0-9]+$ ]] || share_count_current=0

new_shares=0
reset_shares=false
if [[ $share_prev_inode != "$log_inode" ]] || (( share_count_current < share_prev_count )); then
  reset_shares=true
else
  new_shares=$(( share_count_current - share_prev_count ))
fi
(( new_shares < 0 )) && new_shares=0

accepted_prev=0
if ! $reset_shares; then
  accepted_prev=$(get_previous_accepted)
  if (( share_prev_total > accepted_prev )); then
    accepted_prev=$share_prev_total
  fi
fi

accepted_total=$(( accepted_prev + new_shares ))
(( accepted_total < 0 )) && accepted_total=0

printf '%s %s %s\n' "$log_inode" "$share_count_current" "$accepted_total" > "$SHARE_STATE_FILE" 2>/dev/null || true

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
hs_arr=()
temp_out=()
fan_out=()
bus_out=()
have_temp_orig=false
have_fan_orig=false
have_bus_orig=false

(( ${#temp_arr[@]} > 0 )) && have_temp_orig=true
(( ${#fan_arr[@]}  > 0 )) && have_fan_orig=true
(( ${#bus_arr[@]}  > 0 )) && have_bus_orig=true

for ((i=0; i<gpu_count; i++)); do
  if [[ -n ${skip_idx[$i]:-} ]]; then
    continue
  fi
  raw=${hs_map[$i]:-0}
  if [[ $raw == 0 ]]; then
    kh=0
  else
    kh=$(awk -v v="$raw" 'BEGIN { printf "%.3f", v/1000 }')
  fi
  hs_arr+=("$kh")
  if $have_temp_orig; then
    temp_out+=("${temp_arr[i]:-0}")
  fi
  if $have_fan_orig; then
    fan_out+=("${fan_arr[i]:-0}")
  fi
  if $have_bus_orig; then
    bus_out+=("${bus_arr[i]:-0}")
  fi
done

have_temp=false
have_fan=false
have_bus=false

(( ${#temp_out[@]} > 0 )) && have_temp=true
(( ${#fan_out[@]}  > 0 )) && have_fan=true
(( ${#bus_out[@]}  > 0 )) && have_bus=true

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

if uptime=$(get_proc_uptime); then
  :
elif [[ -f $LOG_FILE ]]; then
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
    --arg accepted "$accepted_total" \
    '{
      hs: $hs,
      hs_units: "khs",
      temp: $temp,
      fan: $fan,
      uptime: $uptime,
      ver: $ver,
      ar: [($accepted | tonumber), 0],
      bus_numbers: $bus,
      total_khs: ($total | tonumber)
    } | if $algo == "" then . else . + {algo: $algo} end'
  )
else
  ver_json=$(json_escape "$VERSION_VALUE")
  stats="{\"hs\":$hs_json,\"hs_units\":\"khs\",\"temp\":$temp_json,\"fan\":$fan_json,\"uptime\":$uptime,\"ver\":\"$ver_json\",\"ar\":[${accepted_total},0],\"bus_numbers\":$bus_json,\"total_khs\":$sum_khs"
  if [[ -n $ALGO_VALUE ]]; then
    algo_json=$(json_escape "$ALGO_VALUE")
    stats+=",\"algo\":\"$algo_json\"}"
  else
    stats+='}'
  fi
fi

[[ -z $sum_khs ]] && sum_khs=0
[[ -z $stats ]] && stats='{"hs":[],"hs_units":"khs","temp":[],"fan":[],"uptime":0,"ver":"","ar":[${accepted_total},0],"total_khs":0}'

echo "$sum_khs"
echo "$stats"
