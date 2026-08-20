#!/bin/sh

###############################################################################
# MACsec Manager - Start
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/common.sh"

###############################################################################
# INIT
###############################################################################

load_config
validate_config
check_root

echo
echo "Starting MACsec..."
echo

###############################################################################
# STEP 1 - VERIFY PHYSICAL INTERFACE
###############################################################################

echo "[1/5] Verifying physical interface..."

if ! ip link show "$PHYSICAL_IF" >/dev/null 2>&1; then

    echo "  FAILED"
    echo "  Interface $PHYSICAL_IF not found"

    log_error "Physical interface $PHYSICAL_IF not found"

    exit 1
fi

echo "  OK"

###############################################################################
# STEP 2 - DEPLOY WPA CONFIGURATION
###############################################################################

echo "[2/5] Generating WPA configuration..."

generate_wpa_config

echo "  OK"

log_info "WPA configuration generated"

###############################################################################
# STEP 3 - START WPA_SUPPLICANT
###############################################################################

echo "[3/5] Starting wpa_supplicant..."

if is_wpa_running; then

    echo "  Already running"

else

    wpa_supplicant -d \
        -D macsec_linux \
        -i "$PHYSICAL_IF" \
        -c "$WPA_CONF" \
        -B \
        -f "$WPA_LOG"

    sleep 2
fi

if ! is_wpa_running; then

    echo "  FAILED"

    log_error "Failed to start wpa_supplicant"

    exit 1
fi

echo "  OK"

log_info "wpa_supplicant started"

###############################################################################
# STEP 4 - CONFIGURE MACSEC INTERFACE
###############################################################################

echo "[4/5] Configuring MACsec interface..."

if is_macsec_exist; then
    echo "  Interface found: $MACSEC_IF"
else
    echo "  Creating MACSec interface ${MACSEC_IF}"
    if ip link add link ${PHYSICAL_IF} ${MACSEC_IF} type macsec; then
	echo "  MACSec interface setup successfully"
	log_info "  MACSec interface setup successfully"
    else
	echo "  Error: Unable to setup MACSec interface"
	log_error "  Error: Unable to setup MACSec interface"
	exit 1
    fi
fi

# Configure IP address
if [ -n "$MACSEC_IP" ] && [ -n "$MACSEC_PREFIX" ]; then

    ip addr flush dev "$MACSEC_IF" >/dev/null 2>&1

    ip addr add \
        "${MACSEC_IP}/${MACSEC_PREFIX}" \
        dev "$MACSEC_IF"

    echo "  Configured ${MACSEC_IF} with ${MACSEC_IP}/${MACSEC_PREFIX}"
    log_info \
        "Configured ${MACSEC_IF} with ${MACSEC_IP}/${MACSEC_PREFIX}"

else
    echo "  Error: IPV4_ADDR or PREFIX_LEN not configured!"
    log_error "IPV4_ADDR or PREFIX_LEN not configured"
fi

# Bring interface UP
if is_macsec_up; then

    echo "  Interface UP"
    log_info "${MACSEC_IF} is already UP"

else

    if ip link set "${MACSEC_IF}" up; then
        echo "  ${MACSEC_IF} UP"
        log_info "${MACSEC_IF} brought UP"
    else
        echo "  WARNING: failed to bring ${MACSEC_IF} UP"
        log_warn "Failed to bring ${MACSEC_IF} UP"
    fi

fi
###############################################################################
# STEP 5 - VERIFY MACSEC STATE
###############################################################################

echo "[5/5] Verifying MACsec state..."

SCI=$(get_txsc)
CIPHER=$(get_cipher_suite)

[ -z "$SCI" ] && SCI="N/A"
[ -z "$CIPHER" ] && CIPHER="N/A"

echo "  OK"

###############################################################################
# VERIFICATION REPORT
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
    print_field "Interface" "$MACSEC_IF"
else
    print_field "Interface" "NOT FOUND"
fi

print_field "TXSC" "$SCI"
print_field "Cipher Suite" "$CIPHER"

echo

###############################################################################
# RESULT
###############################################################################

STATUS=$(get_overall_status)

case "$STATUS" in

    RUNNING)

        echo "MACsec started successfully."
        log_info "MACsec start completed"
        ;;

    DEGRADED)

        echo "MACsec started with warnings."
        log_warn "MACsec degraded after startup"
        ;;

    *)

        echo "MACsec startup uncertain."
        log_warn "Unexpected startup state"
        ;;

esac

echo
