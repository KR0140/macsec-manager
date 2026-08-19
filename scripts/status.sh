#!/bin/sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/common.sh"

load_config

###############################################################################
# SERVICE
###############################################################################

show_service()
{
    print_header "Service"

    if is_wpa_running; then
        print_field "wpa_supplicant" "RUNNING"
    else
        print_field "wpa_supplicant" "STOPPED"
    fi

    echo
}

###############################################################################
# INTERFACES
###############################################################################

show_interface()
{
    print_header "Interfaces"

    if ! is_macsec_exist; then

        print_field "MACsec" "NOT FOUND"
        echo
        return

    fi

    IF_INFO=$(ip link show "$MACSEC_IF" 2>/dev/null)

    PHY_IF=$(echo "$IF_INFO" \
        | sed -n 's/.*@\(.*\):.*/\1/p')

    IPV4=$(get_ipv4)

    [ -z "$IPV4" ] && IPV4="N/A"

    print_field "Physical" "$PHY_IF"
    print_field "MACsec" "$MACSEC_IF"

    if is_macsec_up; then
        print_field "Admin State" "UP"
    else
        print_field "Admin State" "DOWN"
    fi

    if is_macsec_carrier_up; then
        print_field "Carrier" "UP"
    else
        print_field "Carrier" "DOWN"
    fi

    print_field "IPv4" "$IPV4"

    echo
}

###############################################################################
# SECURITY POLICY
###############################################################################

show_security_policy()
{
    MACSEC_INFO=$(ip macsec show 2>/dev/null)

    [ -z "$MACSEC_INFO" ] && return

    PROTECT=$(echo "$MACSEC_INFO" | awk '/protect/ {print $4}')
    VALIDATE=$(echo "$MACSEC_INFO" | awk '/validate/ {print $6}')
    ENCRYPT=$(echo "$MACSEC_INFO" | awk '/encrypt/ {print $12}')
    REPLAY=$(echo "$MACSEC_INFO" | awk '/replay/ {print $16}')

    print_header "Security Policy"

    print_field "Protection" "$PROTECT"
    print_field "Validation" "$VALIDATE"
    print_field "Encryption" "$ENCRYPT"
    print_field "Replay Protection" "$REPLAY"
    print_field "Cipher Suite" "$(get_cipher_suite)"

    echo
}

###############################################################################
# TXSC
###############################################################################

show_txsc()
{
    SCI=$(get_txsc)

    [ -z "$SCI" ] && return

    print_header "Transmit Secure Channel"

    print_field "SCI" "$SCI"
    print_field "Active SA" "$(get_active_sa)"

    echo
}

###############################################################################
# STATISTICS
###############################################################################

show_stats()
{
    if ! is_macsec_exist; then
        return
    fi

    STATS=$(ip -s link show "$MACSEC_IF")

    RX_LINE=$(echo "$STATS" | awk '/RX:/ {getline; print}')
    TX_LINE=$(echo "$STATS" | awk '/TX:/ {getline; print}')

    RX_PKTS=$(echo "$RX_LINE" | awk '{print $2}')
    RX_ERRS=$(echo "$RX_LINE" | awk '{print $3}')
    RX_DROP=$(echo "$RX_LINE" | awk '{print $4}')

    TX_PKTS=$(echo "$TX_LINE" | awk '{print $2}')
    TX_ERRS=$(echo "$TX_LINE" | awk '{print $3}')
    TX_DROP=$(echo "$TX_LINE" | awk '{print $4}')

    print_header "Traffic Statistics"

    print_field "RX Packets" "$RX_PKTS"
    print_field "RX Errors" "$RX_ERRS"
    print_field "RX Dropped" "$RX_DROP"

    echo

    print_field "TX Packets" "$TX_PKTS"
    print_field "TX Errors" "$TX_ERRS"
    print_field "TX Dropped" "$TX_DROP"

    echo
}

###############################################################################
# OVERALL STATUS
###############################################################################

show_overall_status()
{
    STATUS=$(get_overall_status)

    print_header "Overall Status"

    print_field "Status" "$STATUS"

    case "$STATUS" in

        RUNNING)
            print_field "Reason" \
                "MACsec operational"
            ;;

        DEGRADED)
            print_field "Reason" \
                "Interface exists but carrier is down"
            ;;

        STARTING)
            print_field "Reason" \
                "Waiting for MACsec interface"
            ;;

        STOPPED)
            print_field "Reason" \
                "wpa_supplicant not running"
            ;;

    esac

    echo
}

###############################################################################
# MAIN
###############################################################################

echo
echo "MACsec Manager Status"
echo "====================="
echo

show_service
show_interface
show_security_policy
show_txsc
show_stats
show_overall_status
