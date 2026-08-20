#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <interface> <frame.bin>\n",
                argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *filename = argv[2];

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);

    if (len <= 0) {
        fprintf(stderr, "Invalid frame length\n");
        fclose(fp);
        return 1;
    }

    unsigned char *frame = malloc(len);
    if (!frame) {
        perror("malloc");
        fclose(fp);
        return 1;
    }

    if (fread(frame, 1, len, fp) != (size_t)len) {
        perror("fread");
        free(frame);
        fclose(fp);
        return 1;
    }

    fclose(fp);

    int sockfd =
        socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sockfd < 0) {
        perror("socket");
        free(frame);
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name,
            ifname,
            IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        free(frame);
        return 1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));

    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    ssize_t sent =
        sendto(sockfd,
               frame,
               len,
               0,
               (struct sockaddr *)&addr,
               sizeof(addr));

    if (sent < 0) {
        perror("sendto");
        close(sockfd);
        free(frame);
        return 1;
    }

    printf("Interface : %s\n", ifname);
    printf("Frame size: %ld bytes\n", len);
    printf("Sent      : %zd bytes\n", sent);
    printf("Status    : SENT\n");

    close(sockfd);
    free(frame);

    return 0;
}
