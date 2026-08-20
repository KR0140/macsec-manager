#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define DEFAULT_COUNT 1

typedef struct
{
    char interface[IFNAMSIZ];
    char filename[256];
    int count;
} config_t;

static void usage(const char *prog)
{
    printf("\n");
    printf("Usage:\n");
    printf("  %s -i <interface> -f <frame_file> [options]\n", prog);
    printf("\n");
    printf(" [ -i <interface> ] ");
    printf(" [ -f <file> ] ");
    printf(" [ -c <count> ] ");
    printf(" [ -h Show help ]");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -i eth0 -f packet.bin\n", prog);
    printf("  %s -i eth0 -f packet.bin -c 100\n", prog);
    printf("\n");
}

static int parse_args(int argc, char *argv[], config_t *cfg)
{
    int opt;

    memset(cfg, 0, sizeof(*cfg));

    cfg->count = DEFAULT_COUNT;

    while ((opt = getopt(argc, argv, "i:f:c:h")) != -1)
    {
        switch (opt)
        {
        case 'i':
            strncpy(cfg->interface,
                    optarg,
                    sizeof(cfg->interface) - 1);
            break;

        case 'f':
            strncpy(cfg->filename,
                    optarg,
                    sizeof(cfg->filename) - 1);
            break;

        case 'c':
            cfg->count = atoi(optarg);

            if (cfg->count <= 0)
            {
                fprintf(stderr,
                        "Invalid count: %s\n",
                        optarg);
                return -1;
            }
            break;

        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);

        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (cfg->interface[0] == '\0')
    {
        fprintf(stderr, "Missing interface (-i)\n");
        return -1;
    }

    if (cfg->filename[0] == '\0')
    {
        fprintf(stderr, "Missing frame file (-f)\n");
        return -1;
    }

    return 0;
}

static int load_frame(const char *filename,
                      unsigned char **frame,
                      size_t *len)
{
    FILE *fp;
    long size;

    fp = fopen(filename, "rb");

    if (!fp)
    {
        perror("fopen");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);

    if (size <= 0)
    {
        fclose(fp);
        fprintf(stderr, "Invalid frame size\n");
        return -1;
    }

    *frame = malloc(size);

    if (!*frame)
    {
        fclose(fp);
        perror("malloc");
        return -1;
    }

    if (fread(*frame, 1, size, fp) != (size_t)size)
    {
        fclose(fp);
        free(*frame);
        perror("fread");
        return -1;
    }

    fclose(fp);

    *len = size;

    return 0;
}

static int open_raw_socket(const char *ifname,
                           struct sockaddr_ll *addr)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_PACKET,
                    SOCK_RAW,
                    htons(ETH_P_ALL));

    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name,
            ifname,
            IFNAMSIZ - 1);

    if (ioctl(sockfd,
              SIOCGIFINDEX,
              &ifr) < 0)
    {
        perror("SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }

    memset(addr, 0, sizeof(*addr));

    addr->sll_family = AF_PACKET;
    addr->sll_ifindex = ifr.ifr_ifindex;
    addr->sll_protocol = htons(ETH_P_ALL);

    return sockfd;
}

static int send_frame(int sockfd,
                      struct sockaddr_ll *addr,
                      const unsigned char *frame,
                      size_t len)
{
    ssize_t ret;

    ret = sendto(sockfd,
                 frame,
                 len,
                 0,
                 (struct sockaddr *)addr,
                 sizeof(*addr));

    if (ret < 0)
    {
        perror("sendto");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    config_t cfg;

    unsigned char *frame = NULL;
    size_t frame_len = 0;

    struct sockaddr_ll addr;

    int sockfd;
    int i;

    if (parse_args(argc, argv, &cfg))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (load_frame(cfg.filename,
                   &frame,
                   &frame_len))
    {
        return EXIT_FAILURE;
    }

    sockfd = open_raw_socket(cfg.interface,
                             &addr);

    if (sockfd < 0)
    {
        free(frame);
        return EXIT_FAILURE;
    }

    printf("Interface : %s\n",
           cfg.interface);

    printf("Frame File: %s\n",
           cfg.filename);

    printf("Frame Size: %zu bytes\n",
           frame_len);

    printf("Count     : %d\n\n",
           cfg.count);

    for (i = 0; i < cfg.count; i++)
    {
        if (send_frame(sockfd,
                       &addr,
                       frame,
                       frame_len))
        {
            close(sockfd);
            free(frame);
            return EXIT_FAILURE;
        }

        printf("[%d/%d] sent\n",
               i + 1,
               cfg.count);
    }

    printf("\nStatus    : DONE\n");

    close(sockfd);
    free(frame);

    return EXIT_SUCCESS;
}
