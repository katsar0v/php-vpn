#!/usr/bin/env bash
# php-vpn Docker test lab driver.  Runs from any cwd; only touches the
# `php-vpn-lab` compose project.  See lab/README.md.
set -Eeuo pipefail

LAB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_DIR=$(dirname -- "$LAB_DIR")
STATE_DIR=$LAB_DIR/state
PROJECT=php-vpn-lab

export PHP_VERSION=${PHP_VERSION:-8.4}
export LAB_UID=${LAB_UID:-$(id -u)}
export LAB_GID=${LAB_GID:-$(id -g)}
# compose reads these from the environment; make sure a stray caller env cannot redirect us
unset COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PROJECT_NAME COMPOSE_PATH_SEPARATOR 2>/dev/null || true

COMPOSE_FILES=(-f "$LAB_DIR/compose.yaml")
if [[ ${LAB_WG_GO:-0} == 1 ]]; then
    COMPOSE_FILES+=(-f "$LAB_DIR/compose.wggo.yaml")
    export WG_FORCE_GO=1
fi

die() { echo "lab: $*" >&2; exit 1; }
log() { echo "lab: $*"; }

[[ $PHP_VERSION =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "PHP_VERSION must look like 8.4 (got '$PHP_VERSION')"

# dc: the always-on services; dca: every profile (selftest client included)
dc()  { docker compose -p "$PROJECT" --project-directory "$LAB_DIR" "${COMPOSE_FILES[@]}" "$@"; }
dca() { dc --profile '*' "$@"; }

prepare_state() {
    mkdir -p "$STATE_DIR"/{ca,wg,clients,logs,pcap} "$REPO_DIR/dist/php$PHP_VERSION"
}

so_path() { echo "$REPO_DIR/dist/php$PHP_VERSION/php-vpn.so"; }

exec_flags() {
    EXEC_FLAGS=()
    [[ -t 0 && -t 1 ]] || EXEC_FLAGS+=(-T)
    if [[ -n ${LAB_EXEC_USER:-} ]]; then EXEC_FLAGS+=(-u "$LAB_EXEC_USER"); fi
}

usage() {
    cat <<USAGE
usage: lab.sh <command> [args]     (PHP_VERSION=8.4 by default; 8.0 .. 8.5)

  up                       build images, start the lab, wait until healthy
  down                     stop and remove containers/networks (keeps lab/state)
  reset                    down + delete lab/state (new keys, CA, logs, pcaps)
  status                   containers, php version, extension presence, tunnel
  logs [svc] [args]        docker compose logs (default: all services, tail 100)
  restart [svc...]         recreate PHP containers (use after (re)building the .so)
  selftest                 validate the lab itself (starts the wg-client container)
  capture start <name> [iface]   tcpdump in php-cli's netns -> lab/state/pcap/<name>.pcap (iface default: any)
  capture stop  <name>           stop + flush
  tunnel down|up           ip link set wg0 down/up on wg-server
  tunnel drop|undrop       iptables DROP / restore UDP 51820 on wg-server
  exec <svc> <cmd...>      run a command in a service (LAB_EXEC_USER=user to change user)
  php <args...>            run php in php-cli
  compose <args...>        raw 'docker compose' against the lab project (all profiles enabled)

services: wg-server hostdns echo secret php-cli php-fpm nginx php-apache sniff wg-client(selftest)
USAGE
}

# ------------------------------------------------------------------ up/down
cmd_up() {
    prepare_state
    log "PHP_VERSION=$PHP_VERSION"
    if [[ ${LAB_PULL:-0} == 1 ]]; then dc build --pull; else dc build; fi
    dc up -d --remove-orphans --wait --wait-timeout "${LAB_WAIT_TIMEOUT:-300}"
    if [[ -f $(so_path) ]]; then
        log "extension: $(so_path) present -> loaded into php-cli / php-fpm / php-apache"
    else
        log "extension: $(so_path) NOT present -> PHP containers run without php-vpn (build it, then: lab.sh restart)"
    fi
    log "up. php-cli 198.51.100.40  php-fpm .41  nginx .42 (a.lab.test, b.lab.test)  php-apache .43"
}

cmd_down() {
    dca down --remove-orphans
}

cmd_reset() {
    cmd_down
    if [[ -e $STATE_DIR ]]; then
        if ! rm -rf "$STATE_DIR" 2>/dev/null; then
            log "state has root-owned files; removing them through a throwaway container"
            docker run --rm --pull never --network none -v "$STATE_DIR:/s" alpine:3 \
                sh -c 'find /s -mindepth 1 -delete' || true
            rm -rf "$STATE_DIR"
        fi
    fi
    log "state deleted"
}

cmd_status() {
    echo "project=$PROJECT PHP_VERSION=$PHP_VERSION"
    if [[ -f $(so_path) ]]; then echo "extension: $(so_path) ($(stat -c %s "$(so_path)") bytes)"; else echo "extension: $(so_path) (missing)"; fi
    dca ps -a --format 'table {{.Service}}\t{{.Name}}\t{{.Status}}' || true
    if dc exec -T wg-server true 2>/dev/null; then
        echo "--- wg-server wg0"
        dc exec -T wg-server wg show wg0 2>/dev/null | sed -E 's/(private key: ).*/\1(hidden)/' || true
    fi
}

cmd_logs() {
    local args=("$@")
    if [[ ${#args[@]} -eq 0 ]]; then args=(--tail=100); fi
    dca logs --no-color "${args[@]}"
}

cmd_restart() {
    local svcs=("$@")
    if [[ ${#svcs[@]} -eq 0 ]]; then svcs=(php-cli sniff php-fpm nginx php-apache); fi
    # sniff shares php-cli's network namespace
    case " ${svcs[*]} " in *" php-cli "*) case " ${svcs[*]} " in *" sniff "*) ;; *) svcs+=(sniff) ;; esac ;; esac
    prepare_state
    dc up -d --wait --wait-timeout "${LAB_WAIT_TIMEOUT:-300}" --force-recreate --no-deps "${svcs[@]}"
}

# ------------------------------------------------------------------ capture / tunnel
cmd_capture() {
    local action=${1:-}; local name=${2:-}
    [[ -n $action && -n $name ]] || die "usage: capture start <name> [iface] | capture stop <name>"
    [[ $name =~ ^[A-Za-z0-9._-]+$ ]] || die "capture name may only contain [A-Za-z0-9._-]"
    case $action in
        start)
            local iface=${3:-any}
            dc exec -T sniff bash -c '
                set -e
                name=$1; iface=$2; f=/state/pcap/$name.pcap; pidf=/run/tcpdump-$name.pid
                if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
                    echo "capture $name is already running" >&2; exit 3
                fi
                mkdir -p /state/pcap
                rm -f "$f" "/state/pcap/$name.log"
                setsid tcpdump -i "$iface" -n -U --immediate-mode -s 0 -Z root -w "$f" \
                    >"/state/pcap/$name.log" 2>&1 </dev/null &
                echo $! >"$pidf"
                for _ in $(seq 100); do
                    if grep -q "listening on" "/state/pcap/$name.log"; then exit 0; fi
                    kill -0 "$(cat "$pidf")" 2>/dev/null || break
                    sleep 0.1
                done
                echo "tcpdump failed to start:" >&2; cat "/state/pcap/$name.log" >&2; exit 1
            ' _ "$name" "$iface"
            log "capture '$name' started on $iface -> $STATE_DIR/pcap/$name.pcap"
            ;;
        stop)
            dc exec -T sniff bash -c '
                name=$1; pidf=/run/tcpdump-$name.pid
                if [ ! -f "$pidf" ]; then echo "no capture named $name" >&2; exit 3; fi
                pid=$(cat "$pidf")
                sleep 0.3                       # let in-flight packets arrive
                kill -INT "$pid" 2>/dev/null || true
                for _ in $(seq 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
                if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid"; echo "tcpdump had to be killed" >&2; fi
                rm -f "$pidf"
                grep -E "packets (captured|received|dropped)" "/state/pcap/$name.log" || true
            ' _ "$name"
            log "capture '$name' stopped: $STATE_DIR/pcap/$name.pcap"
            ;;
        *) die "usage: capture start <name> [iface] | capture stop <name>" ;;
    esac
}

cmd_tunnel() {
    local action=${1:-}
    case $action in
        down)   dc exec -T wg-server ip link set dev wg0 down; log "wg0 DOWN on wg-server" ;;
        up)     dc exec -T wg-server ip link set dev wg0 up;   log "wg0 UP on wg-server (established clients re-handshake within ~15s)" ;;
        drop)
            dc exec -T wg-server sh -c '
                iptables -C INPUT  -p udp --dport 51820 -j DROP 2>/dev/null || iptables -I INPUT  -p udp --dport 51820 -j DROP
                iptables -C OUTPUT -p udp --sport 51820 -j DROP 2>/dev/null || iptables -I OUTPUT -p udp --sport 51820 -j DROP'
            log "UDP 51820 now DROPped on wg-server (both directions)" ;;
        undrop)
            dc exec -T wg-server sh -c '
                while iptables -C INPUT  -p udp --dport 51820 -j DROP 2>/dev/null; do iptables -D INPUT  -p udp --dport 51820 -j DROP; done
                while iptables -C OUTPUT -p udp --sport 51820 -j DROP 2>/dev/null; do iptables -D OUTPUT -p udp --sport 51820 -j DROP; done'
            log "UDP 51820 DROP rules removed on wg-server (established clients re-handshake within ~15s)" ;;
        *) die "usage: tunnel down|up|drop|undrop" ;;
    esac
}

# ------------------------------------------------------------------ exec / php
cmd_exec() {
    [[ $# -ge 2 ]] || die "usage: exec <service> <cmd...>"
    exec_flags
    dca exec "${EXEC_FLAGS[@]}" "$@"
}

cmd_php() {
    exec_flags
    dc exec "${EXEC_FLAGS[@]}" php-cli php "$@"
}

main() {
    local cmd=${1:-help}
    [[ $# -gt 0 ]] && shift
    case $cmd in
        up) cmd_up "$@" ;;
        down) cmd_down "$@" ;;
        reset) cmd_reset "$@" ;;
        status) cmd_status "$@" ;;
        logs) cmd_logs "$@" ;;
        restart) cmd_restart "$@" ;;
        selftest) exec "$LAB_DIR/selftest.sh" "$@" ;;
        capture) cmd_capture "$@" ;;
        tunnel) cmd_tunnel "$@" ;;
        exec) cmd_exec "$@" ;;
        php) cmd_php "$@" ;;
        compose) dca "$@" ;;   # raw docker compose against the lab project (all profiles)
        help|-h|--help) usage ;;
        *) usage >&2; exit 2 ;;
    esac
}
main "$@"
