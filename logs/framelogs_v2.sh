#!/bin/sh

###############################################################################
# MACsec Manager - Frame Logger
#
# Capture one Ethernet frame and print:
#   1. Original tcpdump output
#   2. Labelled frame fields
#
# Supported frame types:
#   0x888e - EAPOL-MKA
#   0x88e5 - MACsec
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

. "$BASE_DIR/scripts/common.sh"

CONFIG_FILE="$BASE_DIR/config/macsec_def.conf"

load_config
check_root

###############################################################################
# TEMPORARY FILE
###############################################################################

RAW_FILE="/tmp/macsec_manager_frame.$$"

cleanup()
{
    rm -f "$RAW_FILE"
}

stop_capture()
{
    echo
    echo "Frame capture stopped."
    cleanup
    exit 0
}

trap stop_capture INT TERM
trap cleanup EXIT
###############################################################################
# GENERAL HELPERS
###############################################################################

fail()
{
    echo "ERROR: $*" >&2
    exit 1
}

command_exists()
{
    command -v "$1" >/dev/null 2>&1
}

print_label()
{
    printf "%-22s : %s\n" "$1" "$2"
}

###############################################################################
# HEX HELPERS
###############################################################################

#
# Read LENGTH bytes from HEX_STREAM at byte OFFSET.
#
# Example:
#   get_bytes 0 6
#   returns the first six bytes.
#
get_bytes()
{
    OFFSET="$1"
    LENGTH="$2"

    START_CHAR=$((OFFSET * 2 + 1))
    END_CHAR=$((START_CHAR + LENGTH * 2 - 1))

    echo "$HEX_STREAM" |
        cut -c "${START_CHAR}-${END_CHAR}"
}

#
# Return the last LENGTH bytes of the captured frame.
#
get_last_bytes()
{
    LENGTH="$1"

    TOTAL_CHARS=${#HEX_STREAM}
    REQUIRED_CHARS=$((LENGTH * 2))

    if [ "$TOTAL_CHARS" -lt "$REQUIRED_CHARS" ]; then
        echo ""
        return
    fi

    START_CHAR=$((TOTAL_CHARS - REQUIRED_CHARS + 1))

    echo "$HEX_STREAM" |
        cut -c "${START_CHAR}-${TOTAL_CHARS}"
}

hex_to_dec()
{
    HEX_VALUE="$1"

    if [ -z "$HEX_VALUE" ]; then
        echo "N/A"
        return
    fi

    printf "%d\n" "0x$HEX_VALUE" 2>/dev/null
}

format_mac()
{
    RAW_MAC="$1"

    if [ "${#RAW_MAC}" -ne 12 ]; then
        echo "N/A"
        return
    fi

    echo "$RAW_MAC" |
        sed 's/../&:/g; s/:$//'
}

format_sci()
{
    RAW_SCI="$1"

    if [ "${#RAW_SCI}" -ne 16 ]; then
        echo "N/A"
        return
    fi

    SCI_MAC_HEX=$(echo "$RAW_SCI" | cut -c 1-12)
    SCI_PORT_HEX=$(echo "$RAW_SCI" | cut -c 13-16)

    SCI_PORT=$(hex_to_dec "$SCI_PORT_HEX")

    echo "$(format_mac "$SCI_MAC_HEX")@$SCI_PORT"
}

###############################################################################
# FRAME CAPTURE
###############################################################################

capture_frame()
{
    : > "$RAW_FILE"

    tcpdump \
        -i "$PHYSICAL_IF" \
        -e \
        -xx \
        -c 1 \
        'ether proto 0x888e or ether proto 0x88e5' \
        > "$RAW_FILE" 2>/dev/null

    return $?
}

###############################################################################
# RAW TCPDUMP TO HEX STREAM
###############################################################################
extract_hex_stream()
{
    HEX_STREAM=$(
        awk '
            /^[[:space:]]*0x[0-9a-fA-F]+:/ {
                sub(/^[^:]*:[[:space:]]*/, "")
                gsub(/[[:space:]]/, "")
                printf "%s", $0
            }
        ' "$RAW_FILE" |
            tr 'A-F' 'a-f'
    )

    if [ -z "$HEX_STREAM" ]; then
        return 1
    fi

    FRAME_LENGTH=$((${#HEX_STREAM} / 2))

    if [ "$FRAME_LENGTH" -lt 14 ]; then
        return 1
    fi

    return 0
}


###############################################################################
# ETHERNET HEADER
###############################################################################

parse_ethernet_header()
{
    DST_MAC_HEX=$(get_bytes 0 6)
    SRC_MAC_HEX=$(get_bytes 6 6)
    ETHERTYPE=$(get_bytes 12 2)

    DST_MAC=$(format_mac "$DST_MAC_HEX")
    SRC_MAC=$(format_mac "$SRC_MAC_HEX")
}

print_ethernet_header()
{
    print_label "Destination MAC" "$DST_MAC"
    print_label "Source MAC" "$SRC_MAC"
    print_label "EtherType" "0x$ETHERTYPE"
}

###############################################################################
# MKA PARSER
###############################################################################

parse_mka()
{
    #
    # Ethernet header:
    #
    # Byte 0-5    Destination MAC
    # Byte 6-11   Source MAC
    # Byte 12-13  EtherType
    #
    # EAPOL header:
    #
    # Byte 14     Protocol Version
    # Byte 15     Packet Type
    # Byte 16-17  Packet Body Length
    #

    EAPOL_VERSION_HEX=$(get_bytes 14 1)
    PACKET_TYPE_HEX=$(get_bytes 15 1)
    PACKET_BODY_LENGTH_HEX=$(get_bytes 16 2)

    EAPOL_VERSION=$(hex_to_dec "$EAPOL_VERSION_HEX")
    PACKET_TYPE=$(hex_to_dec "$PACKET_TYPE_HEX")
    PACKET_BODY_LENGTH=$(hex_to_dec "$PACKET_BODY_LENGTH_HEX")

    #
    # MKA Basic Parameter Set:
    #
    # Byte 18     MKA Version
    # Byte 19     Key Server Priority
    # Byte 20     Flags and body-length high bits
    # Byte 21     Body-length low byte
    #

    MKA_VERSION_HEX=$(get_bytes 18 1)
    KEY_SERVER_PRIORITY_HEX=$(get_bytes 19 1)
    FLAGS_HEX=$(get_bytes 20 1)
    BASIC_LENGTH_LOW_HEX=$(get_bytes 21 1)

    MKA_VERSION=$(hex_to_dec "$MKA_VERSION_HEX")
    KEY_SERVER_PRIORITY=$(hex_to_dec "$KEY_SERVER_PRIORITY_HEX")
    FLAGS_VALUE=$(hex_to_dec "$FLAGS_HEX")
    BASIC_LENGTH_LOW=$(hex_to_dec "$BASIC_LENGTH_LOW_HEX")

    #
    # Byte 20:
    #
    # Bit 7     Key Server
    # Bit 6     MACsec Desired
    # Bits 5-4  MACsec Capability
    # Bits 3-0  Parameter-set body-length high bits
    #

    KEY_SERVER=$(( (FLAGS_VALUE >> 7) & 1 ))
    MACSEC_DESIRED=$(( (FLAGS_VALUE >> 6) & 1 ))
    MACSEC_CAPABILITY=$(( (FLAGS_VALUE >> 4) & 3 ))

    BASIC_LENGTH_HIGH=$((FLAGS_VALUE & 15))

    BASIC_BODY_LENGTH=$((BASIC_LENGTH_HIGH * 256 + BASIC_LENGTH_LOW))

    #
    # Fixed fields in Basic Parameter Set body:
    #
    # Byte 22-29  SCI          8 bytes
    # Byte 30-41  Actor MI    12 bytes
    # Byte 42-45  Actor MN     4 bytes
    # Byte 46-49  Agility      4 bytes
    #

    SCI_HEX=$(get_bytes 22 8)
    ACTOR_MI=$(get_bytes 30 12)
    ACTOR_MN_HEX=$(get_bytes 42 4)
    ALGORITHM_AGILITY=$(get_bytes 46 4)

    ACTOR_MN=$(hex_to_dec "$ACTOR_MN_HEX")

    #
    # The fixed Basic Parameter Set body fields occupy 28 bytes:
    #
    # SCI      8
    # MI      12
    # MN       4
    # Agility  4
    #
    # The remaining Basic Parameter Set body is the CKN.
    #

    FIXED_BASIC_BODY_LENGTH=28
    CKN_LENGTH=$((BASIC_BODY_LENGTH - FIXED_BASIC_BODY_LENGTH))

    if [ "$CKN_LENGTH" -gt 0 ]; then
        CKN=$(get_bytes 50 "$CKN_LENGTH")
    else
        CKN="N/A"
    fi

    #
    # MKA ICV is the final 16 bytes of the MKPDU.
    #

    ICV=$(get_last_bytes 16)

    echo
    print_label "Frame Type" "MKA"
    echo

    print_ethernet_header

    echo
    print_label "Protocol Version" "$EAPOL_VERSION"
    print_label "Packet Type" "$PACKET_TYPE"
    print_label "Packet Body Length" "$PACKET_BODY_LENGTH"

    echo
    print_label "MKA Version" "$MKA_VERSION"
    print_label "Key Server Priority" "$KEY_SERVER_PRIORITY"
    print_label "Key Server" "$KEY_SERVER"
    print_label "MACsec Desired" "$MACSEC_DESIRED"
    print_label "MACsec Capability" "$MACSEC_CAPABILITY"

    echo
    print_label "SCI" "$(format_sci "$SCI_HEX")"
    print_label "Actor MI" "$ACTOR_MI"
    print_label "Actor MN" "$ACTOR_MN"
    print_label "Algorithm Agility" "$ALGORITHM_AGILITY"
    print_label "CKN" "$CKN"
    print_label "ICV" "$ICV"
}

###############################################################################
# MACSEC RUNTIME ICV LENGTH
###############################################################################

get_macsec_icv_length()
{
    ip macsec show 2>/dev/null |
        sed -n \
            's/.*ICV length \([0-9][0-9]*\).*/\1/p' |
        head -n 1
}

###############################################################################
# MACSEC PARSER
###############################################################################

parse_macsec()
{
    #
    # SecTAG:
    #
    # Byte 14     TCI + AN
    # Byte 15     SL
    # Byte 16-19  PN
    #
    # SCI at byte 20 is only present when the SC bit is set.
    #

    TCI_AN_HEX=$(get_bytes 14 1)
    SL_HEX=$(get_bytes 15 1)
    PN_HEX=$(get_bytes 16 4)

    TCI_AN_VALUE=$(hex_to_dec "$TCI_AN_HEX")
    SL_VALUE=$(hex_to_dec "$SL_HEX")

    #
    # TCI occupies the upper six bits.
    # AN occupies the lower two bits.
    #

    TCI=$((TCI_AN_VALUE >> 2))
    AN=$((TCI_AN_VALUE & 3))

    #
    # TCI bit layout after shifting:
    #
    # Bit 5  V
    # Bit 4  ES
    # Bit 3  SC
    # Bit 2  SCB
    # Bit 1  E
    # Bit 0  C
    #

    VERSION_BIT=$(( (TCI >> 5) & 1 ))
    END_STATION_BIT=$(( (TCI >> 4) & 1 ))
    SCI_PRESENT_BIT=$(( (TCI >> 3) & 1 ))
    SCB_BIT=$(( (TCI >> 2) & 1 ))
    ENCRYPTED_BIT=$(( (TCI >> 1) & 1 ))
    CHANGED_TEXT_BIT=$((TCI & 1))

    #
    # SL occupies the lower six bits of byte 15.
    #

    SL=$((SL_VALUE & 63))
    PN=$(hex_to_dec "$PN_HEX")

    #
    # SCI is optional.
    #

    if [ "$SCI_PRESENT_BIT" -eq 1 ]; then
        SCI_HEX=$(get_bytes 20 8)
        SCI=$(format_sci "$SCI_HEX")
    else
        SCI="Not present"
    fi

    #
    # Read runtime ICV length directly from ip macsec show.
    #

    ICV_LENGTH=$(get_macsec_icv_length)

    case "$ICV_LENGTH" in
        ''|*[!0-9]*)
            ICV_LENGTH="N/A"
            ICV="N/A"
            ;;

        *)
            ICV=$(get_last_bytes "$ICV_LENGTH")
            ;;
    esac

    echo
    print_label "Frame Type" "MACsec"
    echo

    print_ethernet_header

    echo
    print_label "TCI/AN Octet" "0x$TCI_AN_HEX"
    print_label "TCI" "0x$(printf '%02x' "$TCI")"
    print_label "Version (V)" "$VERSION_BIT"
    print_label "End Station (ES)" "$END_STATION_BIT"
    print_label "SCI Present (SC)" "$SCI_PRESENT_BIT"
    print_label "SCB" "$SCB_BIT"
    print_label "Encrypted (E)" "$ENCRYPTED_BIT"
    print_label "Changed Text (C)" "$CHANGED_TEXT_BIT"

    echo
    print_label "AN" "$AN"
    print_label "SL" "$SL"
    print_label "PN" "$PN"
    print_label "SCI" "$SCI"
    print_label "ICV Length" "$ICV_LENGTH"
    print_label "ICV" "$ICV"
}

###############################################################################
# FRAME DISPATCH
###############################################################################

label_frame()
{
    parse_ethernet_header

    case "$ETHERTYPE" in
        888e)
            parse_mka
            ;;

        88e5)
            parse_macsec
            ;;

        *)
            echo
            echo "Labeling unsupported"
            ;;
    esac
}
###############################################################################
# MAIN LOOP
###############################################################################

command_exists tcpdump ||
    fail "tcpdump is not installed"

ip link show "$PHYSICAL_IF" >/dev/null 2>&1 ||
    fail "Physical interface not found: $PHYSICAL_IF"

echo "Capturing MKA and MACsec frames on $PHYSICAL_IF..."
echo "Press Ctrl+C to stop."
echo

while :
do
    if ! capture_frame; then
        continue
    fi

    if [ ! -s "$RAW_FILE" ]; then
        continue
    fi

    #
    # Print original tcpdump output without modification.
    #
    cat "$RAW_FILE"

    #
    # Convert this individual frame to HEX_STREAM.
    #
    if extract_hex_stream; then
        label_frame
    else
        echo
        echo "Labeling unsupported"
    fi

    #
    # Separate consecutive frames visually.
    #
    echo
    echo
done
