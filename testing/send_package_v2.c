#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define DEFAULT_COUNT       1
#define PCAP_LINKTYPE_ETHERNET 1
#define MAX_FRAME_SIZE      65535

typedef struct
{
    char interface[IFNAMSIZ];
    char filename[PATH_MAX];
    unsigned int count;
} config_t;

/*
 * Classic PCAP global header.
 *
 * Do not rely on compiler structure packing when reading the file.
 * This structure is only used as a convenient in-memory representation.
 */
typedef struct
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

/*
 * Classic PCAP per-packet header.
 */
typedef struct
{
    uint32_t ts_sec;
    uint32_t ts_fraction;
    uint32_t captured_length;
    uint32_t original_length;
} pcap_packet_header_t;

typedef enum
{
    PCAP_BYTE_ORDER_NATIVE,
    PCAP_BYTE_ORDER_SWAPPED
} pcap_byte_order_t;

static void usage(const char *prog)
{
    printf("\n");
    printf("Usage:\n");
    printf("  %s -i <interface> -f <pcap_file> [options]\n", prog);
    printf("\n");

    printf("Required:\n");
    printf("  -i <interface>    Network interface used to transmit the frame\n");
    printf("  -f <file>         Classic PCAP file containing an Ethernet frame\n");
    printf("\n");

    printf("Options:\n");
    printf("  -c <count>        Number of transmissions (default: 1)\n");
    printf("  -h                Show this help message\n");
    printf("\n");

    printf("Examples:\n");
    printf("  %s -i eth0 -f packet.pcap\n", prog);
    printf("  %s -i eth0 -f packet.pcap -c 10\n", prog);
    printf("\n");

    printf("Notes:\n");
    printf("  - The first packet in the PCAP file is transmitted.\n");
    printf("  - The PCAP link type must be Ethernet.\n");
    printf("  - PCAPNG files are not supported by this version.\n");
    printf("  - Raw sockets normally require root privileges.\n");
    printf("\n");
}

static uint16_t swap_u16(uint16_t value)
{
    return (uint16_t)((value >> 8) | (value << 8));
}

static uint32_t swap_u32(uint32_t value)
{
    return ((value & 0x000000FFU) << 24) |
           ((value & 0x0000FF00U) << 8)  |
           ((value & 0x00FF0000U) >> 8)  |
           ((value & 0xFF000000U) >> 24);
}

static int parse_count(const char *value, unsigned int *count)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);

    if (errno != 0 ||
        end == value ||
        *end != '\0' ||
        parsed == 0 ||
        parsed > UINT_MAX)
    {
        fprintf(stderr, "Invalid transmission count: %s\n", value);
        return -1;
    }

    *count = (unsigned int)parsed;

    return 0;
}

static int copy_option_string(char *destination,
                              size_t destination_size,
                              const char *source,
                              const char *option_name)
{
    size_t source_length;

    source_length = strlen(source);

    if (source_length >= destination_size)
    {
        fprintf(stderr,
                "%s value is too long: %s\n",
                option_name,
                source);
        return -1;
    }

    memcpy(destination, source, source_length + 1);

    return 0;
}

static int parse_args(int argc, char *argv[], config_t *cfg)
{
    int opt;

    memset(cfg, 0, sizeof(*cfg));
    cfg->count = DEFAULT_COUNT;

    opterr = 0;

    while ((opt = getopt(argc, argv, "i:f:c:h")) != -1)
    {
        switch (opt)
        {
        case 'i':
            if (copy_option_string(cfg->interface,
                                   sizeof(cfg->interface),
                                   optarg,
                                   "Interface") < 0)
            {
                return -1;
            }
            break;

        case 'f':
            if (copy_option_string(cfg->filename,
                                   sizeof(cfg->filename),
                                   optarg,
                                   "File") < 0)
            {
                return -1;
            }
            break;

        case 'c':
            if (parse_count(optarg, &cfg->count) < 0)
            {
                return -1;
            }
            break;

        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);

        case '?':
            if (optopt == 'i' || optopt == 'f' || optopt == 'c')
            {
                fprintf(stderr,
                        "Option -%c requires an argument\n",
                        optopt);
            }
            else
            {
                fprintf(stderr,
                        "Unknown option: -%c\n",
                        optopt);
            }

            return -1;

        default:
            return -1;
        }
    }

    if (cfg->interface[0] == '\0')
    {
        fprintf(stderr, "Missing required interface option: -i\n");
        return -1;
    }

    if (cfg->filename[0] == '\0')
    {
        fprintf(stderr, "Missing required PCAP file option: -f\n");
        return -1;
    }

    if (optind < argc)
    {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return -1;
    }

    return 0;
}

static int read_exact(FILE *fp,
                      void *buffer,
                      size_t size,
                      const char *description)
{
    size_t bytes_read;

    bytes_read = fread(buffer, 1, size, fp);

    if (bytes_read != size)
    {
        if (ferror(fp))
        {
            fprintf(stderr,
                    "Failed to read %s: %s\n",
                    description,
                    strerror(errno));
        }
        else
        {
            fprintf(stderr,
                    "Unexpected end of file while reading %s\n",
                    description);
        }

        return -1;
    }

    return 0;
}

static int detect_pcap_format(uint32_t magic,
                              pcap_byte_order_t *byte_order,
                              const char **timestamp_resolution)
{
    /*
     * Values as they appear after being read into a little-endian host.
     *
     * 0xa1b2c3d4: native microsecond PCAP
     * 0xd4c3b2a1: byte-swapped microsecond PCAP
     * 0xa1b23c4d: native nanosecond PCAP
     * 0x4d3cb2a1: byte-swapped nanosecond PCAP
     */
    switch (magic)
    {
    case 0xa1b2c3d4U:
        *byte_order = PCAP_BYTE_ORDER_NATIVE;
        *timestamp_resolution = "microsecond";
        return 0;

    case 0xd4c3b2a1U:
        *byte_order = PCAP_BYTE_ORDER_SWAPPED;
        *timestamp_resolution = "microsecond";
        return 0;

    case 0xa1b23c4dU:
        *byte_order = PCAP_BYTE_ORDER_NATIVE;
        *timestamp_resolution = "nanosecond";
        return 0;

    case 0x4d3cb2a1U:
        *byte_order = PCAP_BYTE_ORDER_SWAPPED;
        *timestamp_resolution = "nanosecond";
        return 0;

    case 0x0a0d0d0aU:
        fprintf(stderr,
                "Unsupported capture format: PCAPNG\n"
                "Create a classic PCAP file with tcpdump -w.\n");
        return -1;

    default:
        fprintf(stderr,
                "Unsupported or invalid PCAP magic number: 0x%08x\n",
                magic);
        return -1;
    }
}

static void normalize_global_header(pcap_global_header_t *header,
                                    pcap_byte_order_t byte_order)
{
    if (byte_order != PCAP_BYTE_ORDER_SWAPPED)
    {
        return;
    }

    header->version_major = swap_u16(header->version_major);
    header->version_minor = swap_u16(header->version_minor);
    header->thiszone =
        (int32_t)swap_u32((uint32_t)header->thiszone);
    header->sigfigs = swap_u32(header->sigfigs);
    header->snaplen = swap_u32(header->snaplen);
    header->network = swap_u32(header->network);
}

static void normalize_packet_header(pcap_packet_header_t *header,
                                    pcap_byte_order_t byte_order)
{
    if (byte_order != PCAP_BYTE_ORDER_SWAPPED)
    {
        return;
    }

    header->ts_sec = swap_u32(header->ts_sec);
    header->ts_fraction = swap_u32(header->ts_fraction);
    header->captured_length = swap_u32(header->captured_length);
    header->original_length = swap_u32(header->original_length);
}

static int load_first_pcap_frame(const char *filename,
                                 unsigned char **frame,
                                 size_t *frame_length)
{
    FILE *fp = NULL;
    pcap_global_header_t global_header;
    pcap_packet_header_t packet_header;
    pcap_byte_order_t byte_order;
    const char *timestamp_resolution = NULL;
    unsigned char *buffer = NULL;

    fp = fopen(filename, "rb");

    if (fp == NULL)
    {
        fprintf(stderr,
                "Cannot open PCAP file '%s': %s\n",
                filename,
                strerror(errno));
        return -1;
    }

    if (read_exact(fp,
                   &global_header,
                   sizeof(global_header),
                   "PCAP global header") < 0)
    {
        goto error;
    }

    if (detect_pcap_format(global_header.magic_number,
                           &byte_order,
                           &timestamp_resolution) < 0)
    {
        goto error;
    }

    normalize_global_header(&global_header, byte_order);

    if (global_header.version_major != 2 ||
        global_header.version_minor != 4)
    {
        fprintf(stderr,
                "Unsupported PCAP version: %u.%u\n",
                global_header.version_major,
                global_header.version_minor);
        goto error;
    }

    if (global_header.network != PCAP_LINKTYPE_ETHERNET)
    {
        fprintf(stderr,
                "Unsupported PCAP link type: %u\n"
                "Expected Ethernet link type: %u\n",
                global_header.network,
                PCAP_LINKTYPE_ETHERNET);
        goto error;
    }

    if (read_exact(fp,
                   &packet_header,
                   sizeof(packet_header),
                   "first PCAP packet header") < 0)
    {
        goto error;
    }

    normalize_packet_header(&packet_header, byte_order);

    if (packet_header.captured_length == 0)
    {
        fprintf(stderr, "The first PCAP packet is empty\n");
        goto error;
    }

    if (packet_header.captured_length > MAX_FRAME_SIZE)
    {
        fprintf(stderr,
                "Captured frame is too large: %u bytes\n",
                packet_header.captured_length);
        goto error;
    }

    if (packet_header.captured_length !=
        packet_header.original_length)
    {
        fprintf(stderr,
                "Warning: packet was truncated during capture "
                "(captured=%u, original=%u)\n",
                packet_header.captured_length,
                packet_header.original_length);
    }

    buffer = malloc(packet_header.captured_length);

    if (buffer == NULL)
    {
        fprintf(stderr,
                "Cannot allocate %u bytes: %s\n",
                packet_header.captured_length,
                strerror(errno));
        goto error;
    }

    if (read_exact(fp,
                   buffer,
                   packet_header.captured_length,
                   "first Ethernet frame") < 0)
    {
        goto error;
    }

    fclose(fp);

    *frame = buffer;
    *frame_length = packet_header.captured_length;

    printf("PCAP Format : classic PCAP\n");
    printf("PCAP Version: %u.%u\n",
           global_header.version_major,
           global_header.version_minor);
    printf("Timestamp   : %s resolution\n",
           timestamp_resolution);
    printf("Link Type   : Ethernet\n");

    return 0;

error:
    free(buffer);
    fclose(fp);
    return -1;
}

static int get_interface_index(int sockfd,
                               const char *ifname,
                               int *interface_index)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    if (copy_option_string(ifr.ifr_name,
                           sizeof(ifr.ifr_name),
                           ifname,
                           "Interface") < 0)
    {
        return -1;
    }

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr,
                "Cannot get index for interface '%s': %s\n",
                ifname,
                strerror(errno));
        return -1;
    }

    *interface_index = ifr.ifr_ifindex;

    return 0;
}

static int open_raw_socket(const char *ifname,
                           struct sockaddr_ll *destination)
{
    int sockfd;
    int interface_index;

    sockfd = socket(AF_PACKET,
                    SOCK_RAW,
                    htons(ETH_P_ALL));

    if (sockfd < 0)
    {
        fprintf(stderr,
                "Cannot create raw socket: %s\n",
                strerror(errno));

        if (errno == EPERM || errno == EACCES)
        {
            fprintf(stderr,
                    "Raw sockets require root privileges or "
                    "CAP_NET_RAW.\n");
        }

        return -1;
    }

    if (get_interface_index(sockfd,
                            ifname,
                            &interface_index) < 0)
    {
        close(sockfd);
        return -1;
    }

    memset(destination, 0, sizeof(*destination));

    destination->sll_family = AF_PACKET;
    destination->sll_protocol = htons(ETH_P_ALL);
    destination->sll_ifindex = interface_index;
    destination->sll_halen = ETH_ALEN;

    return sockfd;
}

static int send_frame(int sockfd,
                      const struct sockaddr_ll *destination,
                      const unsigned char *frame,
                      size_t frame_length)
{
    ssize_t bytes_sent;

    bytes_sent = sendto(sockfd,
                        frame,
                        frame_length,
                        0,
                        (const struct sockaddr *)destination,
                        sizeof(*destination));

    if (bytes_sent < 0)
    {
        fprintf(stderr,
                "Failed to send Ethernet frame: %s\n",
                strerror(errno));
        return -1;
    }

    if ((size_t)bytes_sent != frame_length)
    {
        fprintf(stderr,
                "Partial frame transmission: sent %zd of %zu bytes\n",
                bytes_sent,
                frame_length);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    config_t cfg;
    unsigned char *frame = NULL;
    size_t frame_length = 0;
    struct sockaddr_ll destination;
    int sockfd = -1;
    unsigned int i;
    unsigned int successful_transmissions = 0;

    if (parse_args(argc, argv, &cfg) < 0)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (load_first_pcap_frame(cfg.filename,
                              &frame,
                              &frame_length) < 0)
    {
        return EXIT_FAILURE;
    }

    sockfd = open_raw_socket(cfg.interface,
                             &destination);

    if (sockfd < 0)
    {
        free(frame);
        return EXIT_FAILURE;
    }

    printf("\n");
    printf("Interface : %s\n", cfg.interface);
    printf("Frame File: %s\n", cfg.filename);
    printf("Frame Size: %zu bytes\n", frame_length);
    printf("Count     : %u\n", cfg.count);
    printf("\n");

    for (i = 0; i < cfg.count; ++i)
    {
        if (send_frame(sockfd,
                       &destination,
                       frame,
                       frame_length) < 0)
        {
            fprintf(stderr,
                    "[%u/%u] failed\n",
                    i + 1,
                    cfg.count);
            break;
        }

        successful_transmissions++;

        printf("[%u/%u] sent\n",
               i + 1,
               cfg.count);
	usleep(1000000);
    }

    printf("\n");
    printf("Sent      : %u/%u frames\n",
           successful_transmissions,
           cfg.count);

    if (successful_transmissions == cfg.count)
    {
        printf("Status    : DONE\n");
    }
    else
    {
        printf("Status    : FAILED\n");
    }

    close(sockfd);
    free(frame);

    return successful_transmissions == cfg.count
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
