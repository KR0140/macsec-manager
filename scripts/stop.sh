#!/bin/sh

###############################################################################
# MACsec Manager - Stop
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/common.sh"

###############################################################################
# INIT
###############################################################################

load_config
check_root

echo
echo "Stopping MACsec..."
echo

###############################################################################
# STEP 1 - STOP WPA_SUPPLICANT
###############################################################################

if is_wpa_running; then

    echo "[1/2] Stopping wpa_supplicant..."

    killall wpa_supplicant >/dev/null 2>&1

    sleep 1

    if is_wpa_running; then
        echo "  FAILED"
        log_error "Failed to stop wpa_supplicant"
    else
        echo "  OK"
        log_info "wpa_supplicant stopped"
    fi

else

    echo "[1/2] wpa_supplicant already stopped"

fi

###############################################################################
# STEP 2 - DELETE MACSEC INTERFACE
###############################################################################

if is_macsec_exist; then

    echo "[2/2] Deleting MACsec interface..."

    ip link delete "$MACSEC_IF" >/dev/null 2>&1

    sleep 1

    if is_macsec_exist; then
        echo "  FAILED"
        log_error "Failed to delete $MACSEC_IF"
    else
        echo "  OK"
        log_info "$MACSEC_IF deleted"
    fi

else

    echo "[2/2] MACsec interface already removed"

fi

###############################################################################
# VERIFY
###############################################################################

echo
echo "Verification"
echo "------------"

if is_wpa_running; then
    print_field "wpa_supplicant" "RUNNING"
else
    print_field "wpa_supplicant" "STOPPED"
fi

if is_macsec_exist; then
    print_field "$MACSEC_IF" "EXISTS"
else
    print_field "$MACSEC_IF" "REMOVED"
fi

echo

###############################################################################
# RESULT
###############################################################################

if ! is_wpa_running && ! is_macsec_exist; then

    echo "MACsec stopped successfully."
    log_info "MACsec stop completed"

else

    echo "MACsec stop completed with warnings."
    log_warn "MACsec stop completed with warnings"

fi

echo
