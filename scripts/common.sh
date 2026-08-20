#!/bin/sh

###############################################################################
# MACsec Manager - Common Library
###############################################################################

COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"

CONFIG_FILE="$COMMON_DIR/../config/macsec_def.conf"

LOG_FILE="$COMMON_DIR/../debug/macsec_manager.log"

WPA_CONF="/etc/wpa_supplicant.conf"

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

validate_config()
{
    REQUIRED_VARS="
        PHYSICAL_IF
        MACSEC_IF

        MKA_CAK
        MKA_CKN

        MACSEC_IP
        MACSEC_PREFIX

        MACSEC_POLICY
        MACSEC_INTEG_ONLY

        MACSEC_REPLAY_PROTECT
        MACSEC_REPLAY_WINDOW

        MKA_PRIORITY
        MACSEC_PORT
    "

    for VAR in $REQUIRED_VARS
    do
        eval VALUE=\$$VAR

        if [ -z "$VALUE" ]; then
            echo "ERROR: $VAR is not configured"
            exit 1
        fi
    done
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
# WPA CONFIG
###############################################################################

generate_wpa_config()
{
    cat > "$WPA_CONF" <<EOF
eapol_version=3
ap_scan=0
fast_reauth=1

network={
        key_mgmt=NONE
        eapol_flags=0

        macsec_policy=$MACSEC_POLICY

        mka_cak=$MKA_CAK
        mka_ckn=$MKA_CKN

        mka_priority=$MKA_PRIORITY

        macsec_port=$MACSEC_PORT

        macsec_integ_only=$MACSEC_INTEG_ONLY

        macsec_replay_protect=$MACSEC_REPLAY_PROTECT
        macsec_replay_window=$MACSEC_REPLAY_WINDOW
}
EOF
}

###############################################################################
# EOF
###############################################################################

