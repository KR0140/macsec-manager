#!/bin/sh

###############################################################################
# MACsec Manager - Runtime Information
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/../scripts/common.sh"

load_config

###############################################################################
# VALIDATION
###############################################################################

if [ ! -f "$WPA_LOG" ]; then
    echo "ERROR: wpa_supplicant log not found: $WPA_LOG"
    exit 1
fi

###############################################################################
# CURRENT WPA SESSION
#
# WPA_LOG có thể chứa nhiều phiên do restart.
# Chỉ lấy nội dung từ lần khởi động wpa_supplicant gần nhất.
###############################################################################

SESSION_LOG="/tmp/macsec_manager_wpa_session.$$"

START_LINE=$(
    grep -n "^wpa_supplicant v" "$WPA_LOG" 2>/dev/null \
        | tail -n 1 \
        | cut -d: -f1
)

if [ -n "$START_LINE" ]; then
    tail -n +"$START_LINE" "$WPA_LOG" > "$SESSION_LOG"
else
    cp "$WPA_LOG" "$SESSION_LOG"
fi

cleanup()
{
    rm -f "$SESSION_LOG"
}

trap cleanup EXIT INT TERM

###############################################################################
# HELPERS
###############################################################################

value_or_na()
{
    if [ -n "$1" ]; then
        echo "$1"
    else
        echo "N/A"
    fi
}

get_local_mac()
{
    grep "Own MAC address:" "$SESSION_LOG" 2>/dev/null \
        | tail -n 1 \
        | sed 's/.*Own MAC address: //'
}

get_local_sci()
{
    grep "Generated SCI:" "$SESSION_LOG" 2>/dev/null \
        | tail -n 1 \
        | sed 's/.*Generated SCI: //'
}

get_local_mi()
{
    grep -E "Selected random MI:|Selected a new random MI:" \
        "$SESSION_LOG" 2>/dev/null \
        | tail -n 1 \
        | sed \
            -e 's/.*Selected random MI: //' \
            -e 's/.*Selected a new random MI: //'
}

get_peer_mac()
{
    grep "RX EAPOL from " "$SESSION_LOG" 2>/dev/null \
        | tail -n 1 \
        | sed -n 's/.*RX EAPOL from \([^ ]*\).*/\1/p'
}

get_ckn()
{
    grep "CKN - hexdump" "$SESSION_LOG" 2>/dev/null \
        | tail -n 1 \
        | sed 's/.*CKN - hexdump(len=[0-9]*): //' \
        | tr -d '[:space:]'
}

#
# Lấy Key Server Priority từ MKPDU local mới nhất.
# Chỉ nhận block nằm sau "Encode and send an MKPDU".
#

get_local_key_server_priority()
{
    awk '
        /Encode and send an MKPDU/ {
            outgoing = 1
            next
        }

        outgoing && /Key Server Priority:/ {
            value = $NF
            outgoing = 0
        }

        END {
            if (value != "")
                print value
        }
    ' "$SESSION_LOG"
}

#
# Lấy Actor MN từ MKPDU local mới nhất.
# Tránh lấy nhầm MN trong received MKPDU.
#

get_local_actor_mn()
{
    awk '
        /Encode and send an MKPDU/ {
            outgoing = 1
            next
        }

        outgoing && /Actor'\''s Message Number:/ {
            value = $NF
            outgoing = 0
        }

        END {
            if (value != "")
                print value
        }
    ' "$SESSION_LOG"
}

#
# Lấy Key Server flag từ received MKPDU mới nhất.
#

get_peer_key_server_flag()
{
    awk '
        /Decode received MKPDU/ {
            received = 1
            next
        }

        received && /^[[:space:]]*Key Server:/ {
            value = $NF
            received = 0
        }

        END {
            if (value != "")
                print value
        }
    ' "$SESSION_LOG"
}

###############################################################################
# LOCAL PARTICIPANT IDENTITY
###############################################################################

show_identity()
{
    LOCAL_MAC=$(get_local_mac)
    LOCAL_SCI=$(get_local_sci)
    LOCAL_MI=$(get_local_mi)

    print_header "Local Participant Identity"

    print_field "Interface" \
        "$(value_or_na "$PHYSICAL_IF")"

    print_field "Local MAC" \
        "$(value_or_na "$LOCAL_MAC")"

    print_field "SCI" \
        "$(value_or_na "$LOCAL_SCI")"

    print_field "Member Identifier (MI)" \
        "$(value_or_na "$LOCAL_MI")"

    echo
}

###############################################################################
# PEER INFORMATION
###############################################################################

show_peer_information()
{
    PEER_MAC=$(get_peer_mac)

    print_header "Peer Information"

    print_field "Peer MAC" \
        "$(value_or_na "$PEER_MAC")"

    echo
}

###############################################################################
# MKA SESSION
###############################################################################

show_mka_session()
{
    LAST_CONNECTION_EVENT=$(
        grep -E \
            "CTRL-EVENT-CONNECTED|CTRL-EVENT-DISCONNECTED" \
            "$SESSION_LOG" 2>/dev/null \
            | tail -n 1
    )

    case "$LAST_CONNECTION_EVENT" in
        *CTRL-EVENT-CONNECTED*)
            MKA_STATE="CONNECTED"
            ;;
        *CTRL-EVENT-DISCONNECTED*)
            MKA_STATE="DISCONNECTED"
            ;;
        *)
            MKA_STATE="UNKNOWN"
            ;;
    esac

    LAST_PORT_EVENT=$(
        grep "Supplicant port status:" "$SESSION_LOG" 2>/dev/null \
            | tail -n 1
    )

    case "$LAST_PORT_EVENT" in
        *Authorized*)
            PORT_STATUS="AUTHORIZED"
            ;;
        *Unauthorized*)
            PORT_STATUS="UNAUTHORIZED"
            ;;
        *)
            PORT_STATUS="UNKNOWN"
            ;;
    esac

    print_header "MKA Session"

    print_field "State" "$MKA_STATE"
    print_field "Port Status" "$PORT_STATUS"

    echo
}

###############################################################################
# SECURITY POLICY
###############################################################################
show_security_policy()
{
    MACSEC_INFO=$(ip macsec show 2>/dev/null)

    if [ -z "$MACSEC_INFO" ]; then
        return
    fi

    PROTECT=$(echo "$MACSEC_INFO" | awk '/protect/ {print $4}')
    VALIDATE=$(echo "$MACSEC_INFO" | awk '/validate/ {print $6}')
    ENCRYPT=$(echo "$MACSEC_INFO" | awk '/encrypt/ {print $12}')
    REPLAY=$(echo "$MACSEC_INFO" | awk '/replay/ {print $16}')

    ICV_LEN=$(
        echo "$MACSEC_INFO" \
            | sed -n 's/.*ICV length \([0-9][0-9]*\).*/\1/p' \
            | head -n 1
    )

    CIPHER=$(get_cipher_suite)

    print_header "Security Policy"

    print_field "Protect Frames" \
        "$(value_or_na "$PROTECT")"

    print_field "Encryption" \
        "$(value_or_na "$ENCRYPT")"

    print_field "Replay Protection" \
        "$(value_or_na "$REPLAY")"

    print_field "Validation" \
        "$(value_or_na "$VALIDATE")"

    print_field "Cipher Suite" \
        "$(value_or_na "$CIPHER")"

    print_field "ICV Length" \
        "$(value_or_na "$ICV_LEN")"

    echo
}

###############################################################################
# KEY SERVER ELECTION
###############################################################################

determine_key_server()
{
    LOCAL_MAC=$(get_local_mac)
    PEER_MAC=$(get_peer_mac)
    PEER_KS_FLAG=$(get_peer_key_server_flag)

    if grep -q "I am elected as key server" "$SESSION_LOG"; then
        KEY_SERVER_ELECTION="LOCAL_ELECTED"
        KEY_SERVER_MAC="$LOCAL_MAC"
        return
    fi

    #
    # Nếu MKPDU nhận gần nhất quảng bá peer là Key Server,
    # nhưng local log không có thông báo local được bầu.
    #

    if [ "$PEER_KS_FLAG" = "1" ] && [ -n "$PEER_MAC" ]; then
        KEY_SERVER_ELECTION="PEER_ELECTED"
        KEY_SERVER_MAC="$PEER_MAC"
        return
    fi

    KEY_SERVER_ELECTION="UNKNOWN"
    KEY_SERVER_MAC=""
}

###############################################################################
# KEY METADATA
###############################################################################

show_key_metadata()
{
    CKN=$(get_ckn)
    KS_PRIORITY=$(get_local_key_server_priority)
    ACTOR_MN=$(get_local_actor_mn)

    determine_key_server

    print_header "Key Metadata"

    print_field "CKN" \
        "$(value_or_na "$CKN")"

    print_field "Key Server Priority" \
        "$(value_or_na "$KS_PRIORITY")"

    print_field "Key Server Election" \
        "$KEY_SERVER_ELECTION"

    print_field "Key Server MAC" \
        "$(value_or_na "$KEY_SERVER_MAC")"

    print_field "Latest Actor MN" \
        "$(value_or_na "$ACTOR_MN")"

    echo
}

###############################################################################
# MAIN
###############################################################################

echo
echo "MACsec Runtime Information"
echo "=========================="
echo

show_identity
show_peer_information
show_mka_session
show_security_policy
show_key_metadata

exit 0
