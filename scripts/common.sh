#!/bin/sh

###############################################################################
# MACsec Manager - Common Library
###############################################################################

COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"

CONFIG_FILE="$COMMON_DIR/../config/macsec_def.conf"

###############################################################################
# CONFIG
###############################################################################

load_config()
{
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "ERROR: Config file not found: $CONFIG_FILE"
        exit 1
    fi

    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
}

###############################################################################
# CHECK
###############################################################################

check_root()
{
    if [ "$(id -u)" != "0" ]; then
        echo "ERROR: Must run as root"
        exit 1
    fi
}

is_wpa_running()
{
    pidof wpa_supplicant >/dev/null 2>&1
}

is_macsec_exist()
{
    ip link show "$MACSEC_IF" >/dev/null 2>&1
}

is_macsec_up()
{
    ip link show "$MACSEC_IF" 2>/dev/null \
        | grep -q "UP"
}

is_macsec_carrier_up()
{
    ip link show "$MACSEC_IF" 2>/dev/null \
        | grep -vq "NO-CARRIER"
}

###############################################################################
# LOGGING
###############################################################################

_timestamp()
{
    date "+%Y-%m-%d %H:%M:%S"
}

log_info()
{
    echo "[INFO ] $(_timestamp) $*" >> "$LOG_FILE"
}

log_warn()
{
    echo "[WARN ] $(_timestamp) $*" >> "$LOG_FILE"
}

log_error()
{
    echo "[ERROR] $(_timestamp) $*" >> "$LOG_FILE"
}

###############################################################################
# GETTERS
###############################################################################

get_ipv4()
{
    ip -4 addr show "$MACSEC_IF" 2>/dev/null \
        | awk '/inet / {print $2}'
}

get_cipher_suite()
{
    ip macsec show 2>/dev/null \
        | sed -n 's/.*cipher suite: \(.*\), using.*/\1/p'
}

get_txsc()
{
    ip macsec show 2>/dev/null \
        | awk '/TXSC:/ {print $2}'
}

get_active_sa()
{
    ip macsec show 2>/dev/null \
        | awk '/TXSC:/ {print $5}'
}

###############################################################################
# DISPLAY
###############################################################################

print_header()
{
    echo "$1"
    printf '%*s\n' "${#1}" '' | tr ' ' '-'
}

print_field()
{
    printf "%-22s : %s\n" "$1" "$2"
}

###############################################################################
# STATUS
###############################################################################

get_overall_status()
{
    if ! is_wpa_running; then
        echo "STOPPED"
        return
    fi

    if ! is_macsec_exist; then
        echo "STARTING"
        return
    fi

    if ! is_macsec_carrier_up; then
        echo "DEGRADED"
        return
    fi

    echo "RUNNING"
}

###############################################################################
# DEBUG
###############################################################################

dump_runtime_info()
{
    echo "PHYSICAL_IF=$PHYSICAL_IF"
    echo "MACSEC_IF=$MACSEC_IF"
    echo "LOG_FILE=$LOG_FILE"
}

###############################################################################
# EOF
###############################################################################
