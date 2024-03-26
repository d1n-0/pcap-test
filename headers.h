#include <stdint.h>

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_HEADER_LEN 14
#define IP_PROTOCOL 0x0800
#define IP_ADDR_LEN 4
#define TCP_PROTOCOL 6

typedef struct {
    uint8_t dst[ETHERNET_ADDR_LEN];
    uint8_t src[ETHERNET_ADDR_LEN];
    uint16_t ethertype;
} Ethernet_Header, *Ethernet_Header_Ptr;

typedef struct {
    uint8_t version_and_ihl;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src[IP_ADDR_LEN];
    uint8_t dst[IP_ADDR_LEN];
    /* options */
} IP_Header, *IP_Header_Ptr;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_and_reversed;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urg_ptr;
    /* options */
} TCP_Header, *TCP_Header_Ptr;