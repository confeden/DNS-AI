#!/bin/sh
# DNS-AI quick setup for Linux.
#   curl -fsSL https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.sh | sudo sh
#   undo: curl -fsSL https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.sh | sudo sh -s -- --undo
# systemd-resolved (DNS over TLS) where it exists or can be installed; stubby otherwise.
# Plain port 53 is not served by DNS-AI, so nothing here ever writes our addresses as plain DNS.
set -eu

URL=https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.sh
MANIFESTS="https://raw.githubusercontent.com/confeden/DNS-AI/main/endpoints.json https://dns-ai.ru/endpoints.json"
TLS_NAME=dns.dns-ai.ru
BUILTIN_V4="186.246.49.127 192.144.59.14"
BUILTIN_V6="2a0a:2b41:0:500d::53 2a0d:8480:0:67c::14"
STATE=/etc/dns-ai
RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/dns-ai.conf

say()  { printf '%s\n' "$*"; }
warn() { printf '! %s\n' "$*" >&2; }
die()  { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

fetch() {
    if have curl; then curl -fsSL --max-time 10 "$1"
    elif have wget; then wget -qO- -T 10 "$1"
    else return 1; fi
}

# Prints the members of one JSON string array ("v4" / "v6"), one per line. No jq on purpose.
json_list() {
    tr -d '\n\r\t ' | sed -n "s/.*\"$1\":\[\([^]]*\)\].*/\1/p" | tr ',' '\n' | tr -d '"'
}

load_addresses() {
    V4=""; V6=""
    for m in $MANIFESTS; do
        body=$(fetch "$m" 2>/dev/null) || { warn "не удалось прочитать $m"; continue; }
        v4=$(printf '%s' "$body" | json_list v4 | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -n 2 | tr '\n' ' ')
        v6=$(printf '%s' "$body" | json_list v6 | grep ':' | grep -E '^[0-9a-fA-F:]+$' | head -n 2 | tr '\n' ' ')
        if [ -n "$v4" ]; then
            V4=$v4; V6=$v6
            say "Адреса получены: $m"
            return 0
        fi
    done
    V4=$BUILTIN_V4; V6=$BUILTIN_V6
    warn "список адресов недоступен — использую встроенные"
}

systemd_version() {
    systemctl --version 2>/dev/null | head -n 1 | sed -n 's/^systemd \([0-9]*\).*/\1/p'
}

has_resolved_unit() {
    systemctl list-unit-files systemd-resolved.service 2>/dev/null | grep -q '^systemd-resolved\.service'
}

pkg_install() {
    if have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
    elif have dnf; then dnf install -y "$@"
    elif have yum; then yum install -y "$@"
    elif have zypper; then zypper --non-interactive install "$@"
    elif have pacman; then pacman -S --noconfirm --needed "$@"
    elif have apk; then apk add "$@"
    elif have xbps-install; then xbps-install -y "$@"
    else return 1; fi
}

has_global_v6() {
    have ip && [ -n "$(ip -6 addr show scope global 2>/dev/null)" ]
}

backup_resolv_conf() {
    mkdir -p "$STATE"
    if [ ! -e "$STATE/resolv.conf.bak" ] && [ ! -e "$STATE/resolv.conf.link" ]; then
        if [ -L /etc/resolv.conf ]; then
            readlink /etc/resolv.conf > "$STATE/resolv.conf.link"
        elif [ -e /etc/resolv.conf ]; then
            cp -p /etc/resolv.conf "$STATE/resolv.conf.bak"
        fi
    fi
}

# NetworkManager hands DHCP DNS servers to resolved per link; those would be asked too.
nm_ignore_auto_dns() {
    have nmcli || return 0
    systemctl is-active --quiet NetworkManager 2>/dev/null || return 0
    mkdir -p "$STATE"
    nmcli -t -f UUID,TYPE,DEVICE connection show --active 2>/dev/null | while IFS=: read -r uuid type dev; do
        case "$type" in
            loopback|bridge|tun|wireguard|vpn|*docker*|dummy|"") continue ;;
        esac
        nmcli connection modify "$uuid" ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes || continue
        grep -qx "$uuid" "$STATE/nm-connections" 2>/dev/null || printf '%s\n' "$uuid" >> "$STATE/nm-connections"
        [ -n "$dev" ] && nmcli device reapply "$dev" >/dev/null 2>&1 || true
        say "NetworkManager: «$uuid» больше не берёт DNS провайдера"
    done
}

setup_resolved() {
    if ! has_resolved_unit; then
        say "Устанавливаю systemd-resolved…"
        pkg_install systemd-resolved >/dev/null 2>&1 || return 1
        systemctl daemon-reload
        has_resolved_unit || return 1
    fi
    servers=""
    for ip in $V4; do servers="$servers $ip#$TLS_NAME"; done
    if has_global_v6; then
        for ip in $V6; do servers="$servers $ip#$TLS_NAME"; done
    fi
    mkdir -p "$(dirname "$RESOLVED_DROPIN")"
    cat > "$RESOLVED_DROPIN" <<EOF
# DNS-AI — written by $URL
[Resolve]
DNS=${servers# }
DNSOverTLS=yes
Domains=~.
FallbackDNS=
EOF
    nm_ignore_auto_dns
    if systemctl is-active --quiet systemd-networkd 2>/dev/null && ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
        warn "systemd-networkd: DNS из DHCP на интерфейсах может по-прежнему опрашиваться — проверьте resolvectl status"
    fi
    systemctl enable systemd-resolved >/dev/null 2>&1 || true
    systemctl restart systemd-resolved
    case "$(readlink /etc/resolv.conf 2>/dev/null || true)" in
        */run/systemd/resolve/*) ;;
        *)
            backup_resolv_conf
            rm -f /etc/resolv.conf
            ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            ;;
    esac
    BACKEND=resolved
}

stubby_service() {
    if [ -d /run/systemd/system ]; then systemctl enable stubby >/dev/null 2>&1 || true; systemctl restart stubby
    elif have rc-service; then rc-update add stubby default >/dev/null 2>&1 || true; rc-service stubby restart
    elif have sv; then [ -d /var/service/stubby ] || ln -s /etc/sv/stubby /var/service/; sv restart stubby
    else return 1; fi
}

setup_stubby() {
    if ! have stubby; then
        say "Устанавливаю stubby…"
        pkg_install stubby >/dev/null 2>&1 || return 1
        have stubby || return 1
    fi
    mkdir -p "$STATE" /etc/stubby
    if [ -e /etc/stubby/stubby.yml ] && [ ! -e "$STATE/stubby.yml.bak" ]; then
        cp -p /etc/stubby/stubby.yml "$STATE/stubby.yml.bak"
    fi
    {
        say "# DNS-AI — written by $URL"
        say "resolution_type: GETDNS_RESOLUTION_STUB"
        say "dns_transport_list:"
        say "  - GETDNS_TRANSPORT_TLS"
        say "tls_authentication: GETDNS_AUTHENTICATION_REQUIRED"
        say "tls_query_padding_blocksize: 128"
        say "edns_client_subnet_private: 1"
        say "round_robin_upstreams: 1"
        say "idle_timeout: 30000"
        say "listen_addresses:"
        say "  - 127.0.0.1@53"
        say "  - 0::1@53"
        say "upstream_recursive_servers:"
        for ip in $V4 $V6; do
            say "  - address_data: $ip"
            say "    tls_auth_name: \"$TLS_NAME\""
        done
    } > /etc/stubby/stubby.yml
    stubby_service || return 1
    backup_resolv_conf
    [ -L /etc/resolv.conf ] && rm -f /etc/resolv.conf
    printf '# DNS-AI (stubby)\nnameserver 127.0.0.1\nnameserver ::1\n' > /etc/resolv.conf
    warn "DHCP-клиент может перезаписать /etc/resolv.conf; если DNS-AI «слетит», запретите ему менять DNS"
    BACKEND=stubby
}

verify() {
    i=0
    while [ $i -lt 10 ]; do
        if [ "$BACKEND" = resolved ]; then
            resolvectl query dns-ai.ru >/dev/null 2>&1 && break
        else
            getent hosts dns-ai.ru >/dev/null 2>&1 && break
        fi
        i=$((i + 1)); sleep 1
    done
    if [ $i -lt 10 ]; then
        say ""
        say "Готово: DNS идёт через DNS-AI ($BACKEND). Проверка в браузере: https://dns-ai.ru/ip"
        if [ "$BACKEND" = resolved ]; then
            resolvectl status 2>/dev/null | grep -E 'DNSOverTLS|Current DNS Server' | head -n 4 || true
        fi
    else
        warn "имя dns-ai.ru не разрешилось за 10 секунд"
        say "Отменить: curl -fsSL $URL | sudo sh -s -- --undo"
        exit 1
    fi
}

undo() {
    if [ -e "$RESOLVED_DROPIN" ]; then
        rm -f "$RESOLVED_DROPIN"
        systemctl restart systemd-resolved 2>/dev/null || true
        say "systemd-resolved: настройки DNS-AI удалены"
    fi
    if [ -s "$STATE/nm-connections" ] && have nmcli; then
        while read -r uuid; do
            nmcli connection modify "$uuid" ipv4.ignore-auto-dns no ipv6.ignore-auto-dns no 2>/dev/null || continue
            dev=$(nmcli -g GENERAL.DEVICES connection show "$uuid" 2>/dev/null || true)
            [ -n "$dev" ] && nmcli device reapply "$dev" >/dev/null 2>&1 || true
        done < "$STATE/nm-connections"
        say "NetworkManager: DNS провайдера возвращён"
    fi
    if [ -e "$STATE/stubby.yml.bak" ]; then
        cp -p "$STATE/stubby.yml.bak" /etc/stubby/stubby.yml
        stubby_service 2>/dev/null || true
    elif grep -q 'DNS-AI' /etc/stubby/stubby.yml 2>/dev/null; then
        rm -f /etc/stubby/stubby.yml
        if [ -d /run/systemd/system ]; then systemctl disable --now stubby 2>/dev/null || true
        elif have rc-service; then rc-service stubby stop 2>/dev/null || true; rc-update del stubby 2>/dev/null || true
        fi
    fi
    if [ -e "$STATE/resolv.conf.link" ]; then
        rm -f /etc/resolv.conf; ln -s "$(cat "$STATE/resolv.conf.link")" /etc/resolv.conf
    elif [ -e "$STATE/resolv.conf.bak" ]; then
        rm -f /etc/resolv.conf; cp -p "$STATE/resolv.conf.bak" /etc/resolv.conf
    fi
    rm -rf "$STATE"
    say "Готово: настройки DNS-AI удалены."
}

main() {
    [ "$(id -u)" -eq 0 ] || die "нужны права root: curl -fsSL $URL | sudo sh"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        say "Система: ${PRETTY_NAME:-${ID:-Linux}}"
    fi
    if [ "${1:-}" = "--undo" ]; then undo; return 0; fi

    load_addresses
    say "IPv4: $V4"
    [ -n "$V6" ] && say "IPv6: $V6"

    BACKEND=""
    if [ -d /run/systemd/system ]; then
        ver=$(systemd_version)
        if [ -n "$ver" ] && [ "$ver" -ge 247 ]; then
            setup_resolved || warn "systemd-resolved недоступен — пробую stubby"
        else
            warn "systemd ${ver:-?} старше 247 и не умеет проверять имя сертификата — использую stubby"
        fi
    fi
    [ -n "$BACKEND" ] || setup_stubby || die "не удалось установить ни systemd-resolved, ни stubby. Настройте вручную по https://dns-ai.ru/#setup"
    verify
}

main "$@"
