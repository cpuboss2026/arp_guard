#!/bin/bash
# =============================================================================
# arp_guard.sh — ARP flood protection via ebtables
# libvirt/QEMU hook  +  cron sync  +  CLI management
# =============================================================================
#
# INSTALL AS LIBVIRT HOOK:
#   cp arp_guard.sh /etc/libvirt/hooks/qemu
#   chmod +x /etc/libvirt/hooks/qemu
#   # libvirt calls: qemu <domain> <action> <sub-action> <extra>
#
# INSTALL AS CRON (verify/repair rules every 5 min):
#   */5 * * * * /usr/local/sbin/arp_guard.sh cron >> /var/log/arp_guard.log 2>&1
#
# CLI:
#   arp_guard.sh init   [--mode drop|limit] [--limit RATE] [--burst N]
#   arp_guard.sh update [--mode drop|limit] [--limit RATE] [--burst N]
#   arp_guard.sh add    <vm_name> <ip1> [ip2 ...]
#   arp_guard.sh delete <vm_name> [ip1 ip2 ...]
#   arp_guard.sh flush
#   arp_guard.sh show
#   arp_guard.sh cron
# =============================================================================

set -u

# ── config ─────────────────────────────────────────────────────────────────
MAP_FILE="/root/vds_map.txt"
LOG_FILE="/var/log/arp_guard.log"
LOCK_FILE="/var/lock/arp_guard.lock"
LOCK_TIMEOUT=30          # sec to wait for lock; 0 = skip if busy

TABLE="nat"
CHAIN="ARP_GUARD"          # IP VDS (занятые)
CHAIN_FREE="ARP_FREE_IPS"  # свободные IP
CHAIN_LIMIT="ARP_LIMIT"    # overflow: DROP или rate limit
BASE_CHAIN="PREROUTING"
NODE_BRIDGE="vmbr0"

DEFAULT_MODE="drop"
DEFAULT_LIMIT="5000/sec"
DEFAULT_BURST="10000"
FREE_IPS_FILE=""          # путь к файлу свободных IP (опционально, --free-ips)
# ───────────────────────────────────────────────────────────────────────────

EBTABLES="$(command -v ebtables)"
VIRSH="$(command -v virsh)"
IP_CMD="$(command -v ip)"
AWK="$(command -v awk)"
SORT="$(command -v sort)"
GREP="$(command -v grep)"
CUT="$(command -v cut)"
MKTEMP="$(command -v mktemp)"
FLOCK_BIN="$(command -v flock 2>/dev/null || true)"

[ -x "$EBTABLES" ] || { echo "ebtables not found"; exit 1; }
[ -x "$VIRSH"    ] || { echo "virsh not found";    exit 1; }
[ -x "$IP_CMD"   ] || { echo "ip not found";       exit 1; }

touch "$MAP_FILE" "$LOG_FILE" 2>/dev/null || true

MODE="$DEFAULT_MODE"
LIMIT="$DEFAULT_LIMIT"
BURST="$DEFAULT_BURST"

# ── logging ─────────────────────────────────────────────────────────────────
log() {
    local msg="[$(date '+%F %T')] [$$] $*"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    echo "$msg" >&2
}

# ── locking ──────────────────────────────────────────────────────────────────
# flock(1) на fd 200 — атомарно, работает при параллельных hook-вызовах.
# Если flock недоступен — mkdir-lock fallback.
_LOCK_VIA_FLOCK=0

acquire_lock() {
    if [ -n "$FLOCK_BIN" ] && [ -x "$FLOCK_BIN" ]; then
        exec 200>"$LOCK_FILE"
        if ! "$FLOCK_BIN" -w "$LOCK_TIMEOUT" 200; then
            log "LOCK: timeout ${LOCK_TIMEOUT}s — another instance running, skip"
            exit 0
        fi
        _LOCK_VIA_FLOCK=1
    else
        local waited=0
        while ! mkdir "${LOCK_FILE}.lck" 2>/dev/null; do
            sleep 1
            waited=$((waited + 1))
            if [ "$waited" -ge "$LOCK_TIMEOUT" ]; then
                log "LOCK: mkdir timeout — skip"
                exit 0
            fi
        done
        _LOCK_VIA_FLOCK=0
    fi
}

release_lock() {
    [ "$_LOCK_VIA_FLOCK" -eq 0 ] && rmdir "${LOCK_FILE}.lck" 2>/dev/null || true
    # fd 200 + flock released on exit automatically
}

# ── helpers ──────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage:
  $0 init   [--mode drop|limit] [--limit RATE] [--burst N] [--free-ips FILE]
  $0 update [--mode drop|limit] [--limit RATE] [--burst N] [--free-ips FILE]
  $0 add    <vm_name> <ip1> [ip2 ...]
  $0 delete <vm_name> [ip1 ip2 ...]
  $0 flush
  $0 show
  $0 cron

libvirt hook: install as /etc/libvirt/hooks/qemu
  Handles: start, restore, reconnect -> add rules
           stopped, shutdown          -> remove rules
EOF
}

valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local a b c d
    read -r a b c d <<< "$ip"
    local o
    for o in "$a" "$b" "$c" "$d"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

vm_exists() { "$VIRSH" dominfo "$1" >/dev/null 2>&1; }
chain_exists() { "$EBTABLES" -t "$TABLE" -L "$1" >/dev/null 2>&1; }

# ── uplink detection ─────────────────────────────────────────────────────────
# Uplink = физический интерфейс, который является портом бриджа NODE_BRIDGE (vmbr0).
# Именно через него приходит внешний ARP трафик.
# bond0 имеет приоритет если он тоже член бриджа.
get_uplink() {
    # 1. Ищем bond0 среди членов бриджа
    if "$IP_CMD" link show bond0 >/dev/null 2>&1; then
        local bond_master
        bond_master=$("$IP_CMD" -o link show bond0 2>/dev/null \
            | "$AWK" 'match($0,/master ([^ ]+)/,m){print m[1]}')
        if [ "$bond_master" = "$NODE_BRIDGE" ]; then
            echo "bond0"; return 0
        fi
    fi

    # 2. Ищем первый физический интерфейс — член бриджа NODE_BRIDGE,
    #    исключая vnet*/tap*/virbr* (виртуальные порты VM)
    local dev master
    while read -r dev master; do
        [ "$master" = "$NODE_BRIDGE" ] || continue
        case "$dev" in
            vnet*|tap*|virbr*|veth*|fwln*|fwpr*|fwbr*) continue ;;
        esac
        echo "$dev"; return 0
    done < <("$IP_CMD" -o link show 2>/dev/null \
        | "$AWK" 'match($0,/^[0-9]+: ([^:@]+).*master ([^ ]+)/,m){print m[1], m[2]}')

    # 3. Fallback: первый физический UP интерфейс с реальным device (старое поведение)
    "$IP_CMD" -o link show up | "$AWK" -F': ' '
        {
            dev = $2; gsub(/@.*/, "", dev)
            if (dev ~ /^(lo|vmbr[0-9]*|virbr[0-9]*|br[0-9]*|docker[0-9]*|vnet[0-9]+|veth|fwln|fwpr|fwbr|bond[0-9]*)/)
                next
            cmd = "test -e /sys/class/net/" dev "/device && echo yes"
            cmd | getline result; close(cmd)
            if (result != "yes") next
            print dev; exit
        }
    '
}

# ── IP discovery ─────────────────────────────────────────────────────────────
# IP адреса самой ноды на NODE_BRIDGE (vmbr0) — для whitelist
get_node_ips() {
    "$IP_CMD" -o -4 addr show dev "$NODE_BRIDGE" 2>/dev/null \
        | "$AWK" '{print $4}' | "$CUT" -d/ -f1 | "$SORT" -u
}

# Читаем свободные IP из FREE_IPS_FILE (по одному на строку, # — комментарии)
get_free_ips() {
    [ -n "$FREE_IPS_FILE" ] || return 0
    [ -f "$FREE_IPS_FILE" ] || { log "WARNING: free-ips file not found: $FREE_IPS_FILE"; return 0; }
    "$AWK" '/^[[:space:]]*#/{next} /^[[:space:]]*$/{next} {
        gsub(/[[:space:]].*/,""); print
    }' "$FREE_IPS_FILE" | "$SORT" -u
}
# Ищем: <parameter name='IP' value='x.x.x.x'/>
# Пути поиска XML: /etc/libvirt/qemu/<vm>.xml (стандарт libvirt)
#                  /etc/pve/qemu-server/<vmid>.conf (Proxmox, если применимо)
LIBVIRT_XML_DIR="/etc/libvirt/qemu"

# Единый парсер IPv4 из XML libvirt — строго name='IP' (не IPV6)
# Совместим с awk на CentOS 7 / gawk
_parse_ipv4_from_xml() {
    "$AWK" '
        /<parameter/ {
            # строго name="ip" или name='"'"'ip'"'"' без учёта регистра, не ipv6
            low = tolower($0)
            if (low !~ /name="ip"/ && low !~ /name='"'"'ip'"'"'/) next
            # извлекаем value
            tmp = $0
            gsub(/.*[Vv]alue=["'"'"']/, "", tmp)
            gsub(/["'"'"'].*/, "", tmp)
            # проверяем IPv4
            if (tmp ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                n = split(tmp, o, ".")
                if (n==4 && o[1]+0<=255 && o[2]+0<=255 && o[3]+0<=255 && o[4]+0<=255)
                    print tmp
            }
        }
    ' "$@" | sort -u
}

get_vm_ipv4s() {
    local vm="$1"
    local xmlfile result

    for xmlfile in \
        "$LIBVIRT_XML_DIR/${vm}.xml" \
        "/var/run/libvirt/qemu/${vm}.xml" \
        "/run/libvirt/qemu/${vm}.xml"; do
        [ -f "$xmlfile" ] || continue
        result=$(_parse_ipv4_from_xml "$xmlfile")
        if [ -n "$result" ]; then
            log "INFO: got IPs for $vm from $xmlfile: $result"
            echo "$result"
            return 0
        fi
        log "WARNING: $xmlfile found but no IP parsed for $vm"
    done

    log "WARNING: no XML found for $vm in any known location"
    return 1
}

# Версия для CLI/cron — virsh без таймаута (не в контексте хука)
get_vm_ipv4s_virsh() {
    local vm="$1"
    local result
    result=$(get_vm_ipv4s "$vm")
    if [ -n "$result" ]; then
        echo "$result"
        return
    fi
    "$VIRSH" dumpxml "$vm" 2>/dev/null | _parse_ipv4_from_xml
}

# Перестроить MAP_FILE — читаем XML файлы напрямую, без virsh
build_map_from_virsh() {
    local tmp xmlfile vm ip found=0
    tmp="$("$MKTEMP")" || return 1
    : > "$tmp"

    for xmlfile in "$LIBVIRT_XML_DIR"/*.xml; do
        [ -f "$xmlfile" ] || continue
        vm=$(basename "$xmlfile" .xml)
        [ -n "$vm" ] || continue
        while read -r ip; do
            [ -n "$ip" ] && valid_ipv4 "$ip" || continue
            echo "$vm $ip" >> "$tmp"
            log "MAP detect: $vm $ip"
            found=1
        done < <(_parse_ipv4_from_xml "$xmlfile")
    done

    "$SORT" -u "$tmp" > "$MAP_FILE"
    rm -f "$tmp"
    log "MAP rebuilt: $(wc -l < "$MAP_FILE") entries"
    [ "$found" -eq 1 ] || log "WARNING: no IPs found in $LIBVIRT_XML_DIR"
}

# ── ebtables chain management ────────────────────────────────────────────────
ensure_chain() {
    local ch
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        if ! chain_exists "$ch"; then
            "$EBTABLES" -t "$TABLE" -N "$ch"
            log "CREATE chain $ch"
        fi
    done
}

# Удаляем прыжки из PREROUTING для всех наших цепочек
remove_hook() {
    local uplink="$1" ch
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        while "$EBTABLES" -t "$TABLE" -D "$BASE_CHAIN" \
                -p ARP -i "$uplink" -j "$ch" >/dev/null 2>&1; do :; done
        while "$EBTABLES" -t "$TABLE" -D "$BASE_CHAIN" \
                -p ARP -j "$ch" >/dev/null 2>&1; do :; done
    done
    log "REMOVE hooks $BASE_CHAIN -> ($CHAIN $CHAIN_FREE $CHAIN_LIMIT)"
}

# Добавляем три прыжка в PREROUTING в правильном порядке + RETURN для inter-VM
ensure_hook() {
    local uplink="$1"
    local prerouting ch n ok=1

    prerouting=$("$EBTABLES" -t "$TABLE" -L "$BASE_CHAIN" 2>/dev/null)

    # Проверяем что каждый хук есть ровно один раз с правильным uplink
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        n=$(echo "$prerouting" | "$GREP" -c "jump ${ch}" 2>/dev/null)
        n=${n:-0}
        if [ "$n" -ne 1 ]; then
            ok=0; break
        fi
        echo "$prerouting" | "$GREP" "jump ${ch}" | "$GREP" -q "\-i ${uplink}" || { ok=0; break; }
    done

    [ "$ok" -eq 1 ] && return 0

    log "HOOK: (re)creating all hooks with uplink=$uplink"

    # Удаляем все старые варианты
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        while "$EBTABLES" -t "$TABLE" -D "$BASE_CHAIN" \
                -p ARP -i "$uplink" -j "$ch" >/dev/null 2>&1; do :; done
        while "$EBTABLES" -t "$TABLE" -D "$BASE_CHAIN" \
                -p ARP -j "$ch" >/dev/null 2>&1; do :; done
    done
    log "REMOVE hooks $BASE_CHAIN -> ($CHAIN $CHAIN_FREE $CHAIN_LIMIT)"

    # Добавляем в обратном порядке через -I 1
    "$EBTABLES" -t "$TABLE" -I "$BASE_CHAIN" 1 -p ARP -i "$uplink" -j "$CHAIN_LIMIT"
    "$EBTABLES" -t "$TABLE" -I "$BASE_CHAIN" 1 -p ARP -i "$uplink" -j "$CHAIN_FREE"
    "$EBTABLES" -t "$TABLE" -I "$BASE_CHAIN" 1 -p ARP -i "$uplink" -j "$CHAIN"
    log "ADD hooks $BASE_CHAIN[1-3]: ARP -i $uplink -> $CHAIN -> $CHAIN_FREE -> $CHAIN_LIMIT"
}

flush_chain() {
    local ch
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        if chain_exists "$ch"; then
            "$EBTABLES" -t "$TABLE" -F "$ch"
            log "FLUSH chain $ch"
        fi
    done
}

delete_chain() {
    local uplink
    uplink="$(get_uplink)"
    remove_hook "$uplink"
    flush_chain
    local ch
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        if chain_exists "$ch"; then
            "$EBTABLES" -t "$TABLE" -X "$ch" 2>/dev/null && log "DELETE chain $ch" || true
        fi
    done
}

# Overflow policy — только в ARP_LIMIT
apply_overflow_policy() {
    local uplink="$1"
    "$EBTABLES" -t "$TABLE" -F "$CHAIN_LIMIT"
    case "$MODE" in
        drop)
            "$EBTABLES" -t "$TABLE" -A "$CHAIN_LIMIT" -j DROP
            log "RULE $CHAIN_LIMIT: DROP all"
            ;;
        limit)
            "$EBTABLES" -t "$TABLE" -A "$CHAIN_LIMIT" \
                --limit "$LIMIT" --limit-burst "$BURST" -j ACCEPT
            "$EBTABLES" -t "$TABLE" -A "$CHAIN_LIMIT" -j DROP
            log "RULE $CHAIN_LIMIT: LIMIT $LIMIT burst=$BURST then DROP"
            ;;
        *)
            log "ERROR: invalid MODE=$MODE"; exit 1 ;;
    esac
}

# ── full rebuild всех трёх цепочек ──────────────────────────────────────────
#
# PREROUTING:
#   -p ARP -i uplink -j ARP_GUARD      ← IP VDS
#   -p ARP -i uplink -j ARP_FREE_IPS   ← свободные IP
#   -p ARP -i uplink -j ARP_LIMIT      ← остальное: DROP/LIMIT
#   -p ARP ! -i uplink -j RETURN       ← inter-VM (последнее)
#
# ARP_GUARD:    ACCEPT для каждого IP VDS, RETURN в конце
# ARP_FREE_IPS: ACCEPT для каждого свободного IP, RETURN в конце
# ARP_LIMIT:    DROP или LIMIT+DROP
#
build_rules() {
    local uplink vm ip node_ip tmp

    uplink="$(get_uplink)"
    [ -n "$uplink" ] || { log "ERROR: no uplink found"; exit 1; }

    tmp="$("$MKTEMP")" || exit 1
    "$SORT" -u "$MAP_FILE" > "$tmp" && mv "$tmp" "$MAP_FILE"

    ensure_chain
    flush_chain
    remove_hook "$uplink"
    ensure_hook "$uplink"

    log "BUILD RULES uplink=$uplink bridge=$NODE_BRIDGE mode=$MODE"

    # ── ARP_GUARD: ARP Reply + IP ноды + IP VDS ──────────────────────────────

    # ARP Reply — разрешаем (ответы шлюза/провайдера)
    "$EBTABLES" -t "$TABLE" -A "$CHAIN" \
        -p ARP -i "$uplink" --arp-op Reply -j ACCEPT
    log "RULE $CHAIN: ACCEPT ARP Reply -i $uplink"

    # IP адреса самого NODE_BRIDGE (vmbr0) — whitelist ноды
    while read -r node_ip; do
        [ -n "$node_ip" ] || continue
        "$EBTABLES" -t "$TABLE" -A "$CHAIN" \
            -p ARP -i "$uplink" --arp-op Request --arp-ip-dst "$node_ip" -j ACCEPT
        log "RULE $CHAIN: ACCEPT ARP Request -> node $node_ip"
    done < <(get_node_ips)

    # IP VDS из MAP_FILE
    local count=0
    while read -r vm ip; do
        [ -n "$vm" ] && [ -n "$ip" ] || continue
        "$EBTABLES" -t "$TABLE" -A "$CHAIN" \
            -p ARP -i "$uplink" --arp-op Request --arp-ip-dst "$ip" -j ACCEPT
        log "RULE $CHAIN: ACCEPT ARP Request -> $vm $ip"
        count=$((count + 1))
    done < "$MAP_FILE"
    log "RULE $CHAIN: added $count VM IP rules"

    # RETURN — если не совпало, идём дальше по PREROUTING в ARP_FREE_IPS
    "$EBTABLES" -t "$TABLE" -A "$CHAIN" -j RETURN
    log "RULE $CHAIN: RETURN (pass to $CHAIN_FREE)"

    # ── ARP_FREE_IPS: свободные IP ───────────────────────────────────────────
    local free_ip free_count=0
    while read -r free_ip; do
        [ -n "$free_ip" ] && valid_ipv4 "$free_ip" || continue
        "$EBTABLES" -t "$TABLE" -A "$CHAIN_FREE" \
            -p ARP -i "$uplink" --arp-op Request --arp-ip-dst "$free_ip" -j ACCEPT
        log "RULE $CHAIN_FREE: ACCEPT ARP Request -> free $free_ip"
        free_count=$((free_count + 1))
    done < <(get_free_ips)
    log "RULE $CHAIN_FREE: added $free_count free IP rules"

    # RETURN — если не совпало, идём дальше в ARP_LIMIT
    "$EBTABLES" -t "$TABLE" -A "$CHAIN_FREE" -j RETURN
    log "RULE $CHAIN_FREE: RETURN (pass to $CHAIN_LIMIT)"

    # ── ARP_LIMIT: overflow ───────────────────────────────────────────────────
    apply_overflow_policy "$uplink"
}

# ── consistency check (for cron) ─────────────────────────────────────────────
rules_are_consistent() {
    local ch
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        chain_exists "$ch" || return 1
    done
    local uplink
    uplink="$(get_uplink)"
    # все три хука должны быть в PREROUTING с правильным uplink, по одному разу
    local prerouting
    prerouting=$("$EBTABLES" -t "$TABLE" -L "$BASE_CHAIN" 2>/dev/null)
    local n
    for ch in "$CHAIN" "$CHAIN_FREE" "$CHAIN_LIMIT"; do
        echo "$prerouting" | "$GREP" "jump ${ch}" | "$GREP" -q "\-i ${uplink}" || return 1
        n=$(echo "$prerouting" | "$GREP" -c "jump ${ch}" || true)
        [ "${n:-0}" -eq 1 ] || return 1
    done
    # ARP_GUARD: для каждого IP VDS должно быть ACCEPT правило
    local vm ip
    while read -r vm ip; do
        [ -n "$vm" ] && [ -n "$ip" ] || continue
        if ! "$EBTABLES" -t "$TABLE" -L "$CHAIN" 2>/dev/null \
                | "$GREP" -qE "arp-ip-dst ${ip}[^0-9].*ACCEPT|arp-ip-dst ${ip}$"; then
            log "CRON: missing rule in $CHAIN for $vm $ip"
            return 1
        fi
    done < "$MAP_FILE"
    # ARP_FREE_IPS: для каждого свободного IP должно быть ACCEPT правило
    local free_ip
    while read -r free_ip; do
        [ -n "$free_ip" ] && valid_ipv4 "$free_ip" || continue
        if ! "$EBTABLES" -t "$TABLE" -L "$CHAIN_FREE" 2>/dev/null \
                | "$GREP" -qE "arp-ip-dst ${free_ip}[^0-9].*ACCEPT|arp-ip-dst ${free_ip}$"; then
            log "CRON: missing rule in $CHAIN_FREE for $free_ip"
            return 1
        fi
    done < <(get_free_ips)
    # ARP_LIMIT: должно быть DROP правило
    "$EBTABLES" -t "$TABLE" -L "$CHAIN_LIMIT" 2>/dev/null \
        | "$GREP" -q "DROP" || return 1
    return 0
}

# ── libvirt hook: vm start / restore / reconnect ─────────────────────────────
hook_vm_start() {
    local domain="$1"
    log "HOOK start: $domain"

    local uplink
    uplink="$(get_uplink)"
    [ -n "$uplink" ] || { log "HOOK start: no uplink, abort"; return 1; }

    ensure_chain
    ensure_hook "$uplink"

    # Проверяем состояние цепочки — считаем RETURN правила
    local return_count
    return_count=$("$EBTABLES" -t "$TABLE" -L "$CHAIN" 2>/dev/null \
        | "$GREP" -c "^-j RETURN" || true)
    return_count=${return_count:-0}

    if [ "$return_count" -eq 0 ]; then
        # Цепочка пустая — строим скелет
        log "HOOK start $domain: chains empty, building skeleton"
        flush_chain

        # ARP_GUARD: Reply + node IPs + RETURN
        "$EBTABLES" -t "$TABLE" -A "$CHAIN" \
            -p ARP -i "$uplink" --arp-op Reply -j ACCEPT
        local node_ip
        while read -r node_ip; do
            [ -n "$node_ip" ] || continue
            "$EBTABLES" -t "$TABLE" -A "$CHAIN" \
                -p ARP -i "$uplink" --arp-op Request --arp-ip-dst "$node_ip" -j ACCEPT
        done < <(get_node_ips)
        "$EBTABLES" -t "$TABLE" -A "$CHAIN" -j RETURN

        # ARP_FREE_IPS: свободные IP + RETURN
        local free_ip
        while read -r free_ip; do
            [ -n "$free_ip" ] && valid_ipv4 "$free_ip" || continue
            "$EBTABLES" -t "$TABLE" -A "$CHAIN_FREE" \
                -p ARP -i "$uplink" --arp-op Request --arp-ip-dst "$free_ip" -j ACCEPT
        done < <(get_free_ips)
        "$EBTABLES" -t "$TABLE" -A "$CHAIN_FREE" -j RETURN

        # ARP_LIMIT: overflow
        apply_overflow_policy "$uplink"
        log "RULE skeleton: built ($CHAIN / $CHAIN_FREE / $CHAIN_LIMIT)"

    elif [ "$return_count" -gt 1 ]; then
        # Мусор в цепочке — несколько RETURN, делаем полную перестройку
        log "HOOK start $domain: dirty chain ($return_count RETURN rules), rebuilding"
        build_map_from_virsh
        build_rules
        return 0
    fi

    # Удаляем дубли IP правил
    dedup_chain

    # Добавляем IP этой VM
    local ip found=0
    while read -r ip; do
        [ -n "$ip" ] && valid_ipv4 "$ip" || continue
        if ! "$GREP" -qxF "$domain $ip" "$MAP_FILE"; then
            echo "$domain $ip" >> "$MAP_FILE"
            log "MAP add: $domain $ip"
        fi
        _hook_add_ip "$domain" "$ip" "$uplink"
        found=1
    done < <(get_vm_ipv4s "$domain")

    [ "$found" -eq 1 ] || log "HOOK start $domain: no IPs found in XML"
}


# ── libvirt hook: vm stop ─────────────────────────────────────────────────────
hook_vm_stop() {
    local domain="$1"
    log "HOOK stop: $domain"

    if ! chain_exists "$CHAIN" && ! chain_exists "$CHAIN_FREE"; then
        log "HOOK stop: chains absent, nothing to do"
        return 0
    fi

    local uplink ip tmp
    uplink="$(get_uplink)"

    # Берём IP из MAP_FILE — не вызываем virsh dumpxml (VM уже останавливается)
    while read -r ip; do
        [ -n "$ip" ] && valid_ipv4 "$ip" || continue
        if "$EBTABLES" -t "$TABLE" -D "$CHAIN" \
                -p ARP -i "$uplink" --arp-op Request --arp-ip-dst "$ip" -j ACCEPT \
                >/dev/null 2>&1; then
            log "RULE del: $domain $ip"
        fi
    done < <("$AWK" -v vm="$domain" '$1==vm {print $2}' "$MAP_FILE")

    # Убираем из MAP_FILE
    tmp="$("$MKTEMP")" || return 1
    "$AWK" -v vm="$domain" '$1 != vm' "$MAP_FILE" > "$tmp"
    mv "$tmp" "$MAP_FILE"
    log "MAP: removed all IPs for $domain"
}

# ── libvirt hook: reconnect ───────────────────────────────────────────────────
# Вызывается когда libvirtd перезапускается и переподключается к QEMU.
# Цепочка могла исчезнуть — переинициализируем правила для этой VM.
hook_vm_reconnect() {
    local domain="$1"
    log "HOOK reconnect: $domain (re-ensuring rules)"
    hook_vm_start "$domain"
}

# ── cron: проверка и восстановление ─────────────────────────────────────────
cmd_cron() {
    log "CRON: checking rules consistency"
    dedup_chain
    if rules_are_consistent; then
        log "CRON: OK, nothing to do"
        return 0
    fi
    log "CRON: inconsistency detected — rebuilding"
    build_map_from_virsh
    build_rules
}

# ── CLI commands ─────────────────────────────────────────────────────────────
cmd_init()   { build_map_from_virsh; build_rules; }
cmd_flush()  { delete_chain; log "FLUSH complete"; }

cmd_update() {
    local uplink vm ip xmlfile found_new=0

    uplink="$(get_uplink)"
    [ -n "$uplink" ] || { log "ERROR: no uplink found"; exit 1; }

    log "UPDATE: scanning $LIBVIRT_XML_DIR for new IPs"

    # Сканируем XML файлы — ищем IP которых ещё нет в MAP_FILE
    local new_entries=()
    for xmlfile in "$LIBVIRT_XML_DIR"/*.xml; do
        [ -f "$xmlfile" ] || continue
        while IFS=" " read -r vm ip; do
            [ -n "$vm" ] && [ -n "$ip" ] || continue
            valid_ipv4 "$ip" || continue
            if ! "$GREP" -qxF "$vm $ip" "$MAP_FILE"; then
                new_entries+=("$vm $ip")
                found_new=1
            fi
        done < <("$AWK" '
            /<name>/ && !name {
                line=$0; gsub(/.*<name>/,"",line); gsub(/<\/name>.*/,"",line)
                if (line != "") name=line
            }
            /<parameter/ && tolower($0) ~ /name="ip"/ || tolower($0) ~ /name='"'"'ip'"'"'/ {
                line=$0
                gsub(/.*[Vv]alue=["'"'"']/,"",line); gsub(/["'"'"'].*/,"",line)
                if (name != "" && line ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) print name, line
            }
        ' "$xmlfile")
    done

    if [ "$found_new" -eq 0 ]; then
        log "UPDATE: no new IPs found, MAP is up to date"
        echo "No new IPs found — MAP is up to date."
        # Всё равно пересобираем правила на случай если они слетели
        build_rules
        return 0
    fi

    # Показываем diff и добавляем новые записи
    echo "New IPs found:"
    local entry
    for entry in "${new_entries[@]}"; do
        echo "  + $entry"
        echo "$entry" >> "$MAP_FILE"
        log "MAP add (update): $entry"
    done

    # Пересортируем MAP_FILE
    local tmp
    tmp="$("$MKTEMP")" || exit 1
    "$SORT" -u "$MAP_FILE" > "$tmp" && mv "$tmp" "$MAP_FILE"

    log "UPDATE: added ${#new_entries[@]} new entries, rebuilding rules"
    build_rules

    echo ""
    echo "Added ${#new_entries[@]} new IP(s). Rules rebuilt."
}

cmd_add() {
    local vm="$1"; shift
    [ -n "$vm" ] || { echo "VM name required"; exit 1; }
    vm_exists "$vm" || { echo "VM not found in virsh: $vm"; exit 1; }
    [ "$#" -ge 1 ]  || { echo "At least one IP required"; exit 1; }
    local ip
    for ip in "$@"; do
        valid_ipv4 "$ip" || { echo "Invalid IP: $ip"; exit 1; }
        "$GREP" -qxF "$vm $ip" "$MAP_FILE" || { echo "$vm $ip" >> "$MAP_FILE"; log "MAP add: $vm $ip"; }
    done
    build_rules
}

cmd_delete() {
    local vm="$1"; shift
    [ -n "$vm" ] || { echo "VM name required"; exit 1; }
    local tmp ips_re="" ip
    tmp="$("$MKTEMP")" || exit 1
    if [ "$#" -eq 0 ]; then
        "$AWK" -v vm="$vm" '$1 != vm' "$MAP_FILE" > "$tmp"
        log "MAP delete all IPs for $vm"
    else
        for ip in "$@"; do
            valid_ipv4 "$ip" || { echo "Invalid IP: $ip"; rm -f "$tmp"; exit 1; }
            ips_re="${ips_re:+${ips_re}|}^${vm}[[:space:]]+${ip}$"
            log "MAP delete: $vm $ip"
        done
        "$GREP" -Ev "$ips_re" "$MAP_FILE" > "$tmp" || true
    fi
    mv "$tmp" "$MAP_FILE"
    build_rules
}

cmd_show() {
    local uplink
    uplink="$(get_uplink 2>/dev/null || echo 'not found')"
    echo "=== TABLE / CHAINS ===";
    echo "  $TABLE / $CHAIN  (IP VDS)"
    echo "  $TABLE / $CHAIN_FREE  (свободные IP)"
    echo "  $TABLE / $CHAIN_LIMIT  (overflow: $MODE)"
    echo
    echo "=== UPLINK ===";          echo "$uplink"; echo
    echo "=== NODE BRIDGE ===";     echo "$NODE_BRIDGE"; echo
    echo "=== NODE IPs on $NODE_BRIDGE ==="; get_node_ips; echo
    echo "=== MAP FILE: $MAP_FILE ($(wc -l < "$MAP_FILE" 2>/dev/null || echo 0) entries) ==="
    cat "$MAP_FILE"; echo
    echo "=== FREE IPs FILE: ${FREE_IPS_FILE:-not set} ==="
    [ -n "$FREE_IPS_FILE" ] && get_free_ips || echo "(not configured)"; echo
    echo "=== MODE: $MODE ==="; [ "$MODE" = "limit" ] && echo "limit=$LIMIT burst=$BURST"; echo
    echo "=== EBTABLES $TABLE $BASE_CHAIN ==="
    "$EBTABLES" -t "$TABLE" -L "$BASE_CHAIN" --Ln --Lc 2>/dev/null || true; echo
    echo "=== EBTABLES $TABLE $CHAIN (IP VDS) ==="
    "$EBTABLES" -t "$TABLE" -L "$CHAIN" --Ln --Lc 2>/dev/null || echo "chain not present"; echo
    echo "=== EBTABLES $TABLE $CHAIN_FREE (свободные IP) ==="
    "$EBTABLES" -t "$TABLE" -L "$CHAIN_FREE" --Ln --Lc 2>/dev/null || echo "chain not present"; echo
    echo "=== EBTABLES $TABLE $CHAIN_LIMIT (overflow) ==="
    "$EBTABLES" -t "$TABLE" -L "$CHAIN_LIMIT" --Ln --Lc 2>/dev/null || echo "chain not present"
}

# ── option parser ────────────────────────────────────────────────────────────
parse_opts() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --mode)     shift; [[ "${1:-}" =~ ^(drop|limit)$ ]] || { echo "Bad --mode"; exit 1; }; MODE="$1" ;;
            --limit)    shift; [ -n "${1:-}" ] || { echo "Missing --limit value"; exit 1; }; LIMIT="$1" ;;
            --burst)    shift; [ -n "${1:-}" ] || { echo "Missing --burst value"; exit 1; }; BURST="$1" ;;
            --free-ips) shift; [ -n "${1:-}" ] || { echo "Missing --free-ips value"; exit 1; }; FREE_IPS_FILE="$1" ;;
        esac
        shift || true
    done
}

# Strip option flags from positional args list
strip_opts() {
    local out=()
    local skip_next=0
    for a in "$@"; do
        if [ "$skip_next" -eq 1 ]; then skip_next=0; continue; fi
        case "$a" in
            --mode|--limit|--burst|--free-ips) skip_next=1 ;;
            *) out+=("$a") ;;
        esac
    done
    printf '%s\n' "${out[@]}"
}

# ── entry point ───────────────────────────────────────────────────────────────
main() {
    local cmd="${1:-}"
    shift || true

    # ── libvirt hook auto-detection ──────────────────────────────────────────
    # Если первый аргумент не является CLI-командой — мы вызваны как libvirt hook.
    # libvirt: /etc/libvirt/hooks/qemu <domain> <action> <sub-action> <extra>
    case "$cmd" in
        init|update|add|delete|flush|show|cron)
            # CLI path — fall through
            ;;
        "")
            usage; exit 1 ;;
        *)
            # Hook path: cmd=domain, $1=action
            local domain="$cmd"
            local action="${1:-}"
            local sub="${2:-}"
            local extra="${3:-}"
            log "HOOK called: domain=$domain action=$action sub=$sub extra=$extra"
            case "$action" in
                start|restore)   hook_vm_start    "$domain" ;;
                started)         hook_vm_start    "$domain" ;;
                finish)          hook_vm_finish   "$domain" ;;
                reconnect)       hook_vm_reconnect "$domain" ;;
                stopped|shutdown|stop) hook_vm_stop "$domain" ;;
                migrate)         log "HOOK: migrate initiated for $domain (handled on destination)" ;;
                *)               log "HOOK: unhandled action='$action' sub='${2:-}' for $domain" ;;
            esac
            exit 0
            ;;
    esac

    # ── CLI path ─────────────────────────────────────────────────────────────
    parse_opts "$@"
    acquire_lock
    trap release_lock EXIT

    case "$cmd" in
        init)   cmd_init ;;
        update) cmd_update ;;
        flush)  cmd_flush ;;
        show)   cmd_show ;;
        cron)   cmd_cron ;;

        add)
            local args=()
            mapfile -t args < <(strip_opts "$@")
            [ "${#args[@]}" -ge 2 ] || { usage; exit 1; }
            cmd_add "${args[@]}"
            ;;
        delete)
            local args=()
            mapfile -t args < <(strip_opts "$@")
            [ "${#args[@]}" -ge 1 ] || { usage; exit 1; }
            cmd_delete "${args[@]}"
            ;;
    esac
}

main "$@"
