#!/bin/sh

###############################################################################
# MACsec Manager - Restart
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/common.sh"

###############################################################################
# INIT
###############################################################################

load_config
check_root

echo
echo "Restarting MACsec..."
echo

log_info "MACsec restart requested"

###############################################################################
# STEP 1 - STOP
###############################################################################

echo "[1/2] Stopping MACsec..."
echo

"$SCRIPT_DIR/stop.sh"

STOP_RET=$?

if [ "$STOP_RET" -ne 0 ]; then

    echo
    echo "Restart failed during stop phase."

    log_error "Restart failed during stop phase"

    exit 1
fi

###############################################################################
# STEP 2 - START
###############################################################################

echo
echo "[2/2] Starting MACsec..."
echo

"$SCRIPT_DIR/start.sh"

START_RET=$?

if [ "$START_RET" -ne 0 ]; then

    echo
    echo "Restart failed during start phase."

    log_error "Restart failed during start phase"

    exit 1
fi

###############################################################################
# RESULT
###############################################################################

echo
echo "Restart Verification"
echo "--------------------"

STATUS=$(get_overall_status)

print_field "Status" "$STATUS"

case "$STATUS" in

    RUNNING)

        print_field "Result" "SUCCESS"

        log_info "MACsec restart completed"

        echo
        echo "MACsec restarted successfully."

        exit 0
        ;;

    DEGRADED)

        print_field "Result" "WARNING"

        log_warn "MACsec restarted with warnings"

        echo
        echo "MACsec restarted with warnings."

        exit 0
        ;;

    *)

        print_field "Result" "FAILED"

        log_error "Unexpected restart state: $STATUS"

        echo
        echo "MACsec restart failed."

        exit 1
        ;;

esac
