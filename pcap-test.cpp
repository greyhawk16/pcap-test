#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <libnet.h>
#include <arpa/inet.h>

// ref: https://thfist-1071.tistory.com/122

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_ip_address(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("%s\n", inet_ntoa(ip_addr));
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);     // 패킷 캡처
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // 이더넷 헤더 파싱
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;

        printf("Source MAC:    ");
        for(int i=0; i<ETHER_ADDR_LEN; i++) {
            if(i == ETHER_ADDR_LEN-1) {
                printf("%02X\n",eth_hdr->ether_shost[i]);
            }
            else {
                printf("%02X:",eth_hdr->ether_shost[i]);
            }
        }

        printf("Destination MAC:    ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            if(i ==ETHER_ADDR_LEN - 1) {
                printf("%02X\n", eth_hdr->ether_dhost[i]);
            } else {
                printf("%02X:", eth_hdr->ether_dhost[i]);
            }
        }

        // IP 헤더 파싱
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

        printf("Source IP:    ");
        print_ip_address(ip_hdr->ip_src.s_addr);
        printf("Destination IP:   ");
        print_ip_address(ip_hdr->ip_dst.s_addr);

        // TCP 출발지 포트, 목적지 포트 파싱
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)packet;
        printf("TCP source port:    %d\n", ntohs(tcp_hdr->th_sport));
        printf("TCP destination port:    %d\n", ntohs(tcp_hdr->th_dport));

        uint32_t payload_size = 14 + (ip_hdr->ip_hl)*4 + (tcp_hdr->th_off)*4;
        printf("Packet payload:    ");
        for (int i = payload_size; i < payload_size+20; i++) {
            printf("0x%02X ", packet[i]);
        }

        printf("\n");
        printf("%u bytes captured\n", header->caplen);
        printf("\n\n");
    }

    pcap_close(pcap);
    return 0;
}
