#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include "headers.h"

void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(uint8_t *mac)
{
    for (int i = 0; i < ETHERNET_ADDR_LEN; i++)
    {
        printf("%02x", mac[i]);
        if (i != 5)
            printf(":");
    }
    printf("\n");
}

void print_ip(uint8_t *ip)
{
    for (int i = 0; i < IP_ADDR_LEN; i++)
    {
        printf("%d", ip[i]);
        if (i != 3)
            printf(".");
    }
    printf("\n");
}

void print_payload(uint8_t *payload, uint16_t len)
{
    if (len > 20)
        len = 20;
    for (int i = 0; i < len; i++)
    {
        if (i % 8 == 0)
            printf("    ");
        printf("%02x ", payload[i]);
        if (i % 8 == 7)
            printf("\n");
    }
    if (len % 8 != 0)
        printf("\n");
}

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // printf("%u bytes captured\n", header->caplen);

        Ethernet_Header_Ptr eth_hdr = (Ethernet_Header_Ptr)packet;
        if (ntohs(eth_hdr->ethertype) != IP_PROTOCOL)
        {
            printf("Not IP packet\n");
            continue;
        }

        IP_Header_Ptr ip_hdr = (IP_Header_Ptr)(packet + ETHERNET_HEADER_LEN);
        if (ip_hdr->protocol != TCP_PROTOCOL)
        {
            printf("Not TCP packet\n");
            continue;
        }
        uint16_t ip_hdr_len = (ip_hdr->version_and_ihl & 0x0f) << 2;

        TCP_Header_Ptr tcp_hdr = (TCP_Header_Ptr)((uint8_t *)ip_hdr + ip_hdr_len);
        uint16_t tcp_hdr_len = (tcp_hdr->data_offset_and_reversed >> 4) << 2;

        uint8_t *payload = (uint8_t *)tcp_hdr + tcp_hdr_len;
        uint16_t payload_len = ntohs(ip_hdr->total_length) - ip_hdr_len - tcp_hdr_len;

        printf("1. Ethernet\n");
        printf("    dst mac: ");
        print_mac(eth_hdr->dst);
        printf("    src mac: ");
        print_mac(eth_hdr->src);
        printf("2. IP\n");
        printf("    src ip: ");
        print_ip(ip_hdr->src);
        printf("    dst ip: ");
        print_ip(ip_hdr->dst);
        printf("3. TCP\n");
        printf("    src port: %d\n", ntohs(tcp_hdr->src_port));
        printf("    dst port: %d\n", ntohs(tcp_hdr->dst_port));
        printf("4. Payload\n");
        print_payload(payload, payload_len);
        printf("\n");
    }

    pcap_close(pcap);
}
