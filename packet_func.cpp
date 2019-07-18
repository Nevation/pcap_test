#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "packet_func.h"

void print_mac(u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(u_char* ip) {
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(u_char* port) {
    printf("%d\n", (port[0] << 8) | port[1]);
}

bool check_ether_type_ipv4(u_char* ether_type){
    /*
    switch ((ether_type[0] << 8) | ether_type[1]) {
        case 2048:
            printf("=IPv4");
        break;
        case 34525:
            printf("=IPv6");
        break;
        case 2054:
            printf("=ARP=");
        break;
        default:
            printf("%d\n", (ether_type[0] << 8) | ether_type[1]);
        break;

    }
    */
    return ((ether_type[0] << 8) | ether_type[1]) == 2048;
}

void print_tcp_data(u_char* ether_type){
    int ip_header_size = (ether_type[0] & 0x0F) * 4;
    int tcp_header_size = ((ether_type[46 - IP_LOCATION] & 0xF0) >> 4) * 4;
    int total_size = (ether_type[2] << 8) | ether_type[3];
    int tcp_data_start_location = ip_header_size + tcp_header_size;
    int tcp_data_size = total_size - ip_header_size - tcp_header_size;

    for (int i = 0; i < 10 && i < tcp_data_size;i++ ){
        printf("%02x ", ether_type[tcp_data_start_location + i]);
    }
    printf("\n");
}

bool check_tcp(u_char* ether_type)
{
    return ether_type[0] == 6;
}

void print_packet_information(struct pcap_pkthdr* header, u_char* packet)
{

    printf("=================================\n");
    printf("Byte: %u\n", header->caplen);
    printf("ETHER-DMAC: ");         print_mac(&packet[D_MAC_LOCATION]);
    printf("ETHER-SMAC: ");         print_mac(&packet[S_MAC_LOCATION]);

    if (check_ether_type_ipv4(&packet[ETHER_TYPE_LOCATION])){
        printf("IP-SIP: ");         print_ip(&packet[IP_LOCATION + S_IP_LOCATION]);
        printf("IP-DIP: ");         print_ip(&packet[IP_LOCATION + D_IP_LOCATION]);
        if (check_tcp(&packet[PROTOCOL_LOCATION])){
            printf("TCP-SPORT: ");  print_port(&packet[TCP_LOCATION + S_PORT_LOCATION]);
            printf("TCP-DPORT: ");  print_port(&packet[TCP_LOCATION + D_PORT_LOCATION]);
            printf("TCP-DATA: ");   print_tcp_data(&packet[IP_LOCATION]);
        }
    }

    printf("=================================\n\n");

}
