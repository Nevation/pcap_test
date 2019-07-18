#pragma once
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

//Ethernet Header

#define D_MAC_LOCATION          0
#define S_MAC_LOCATION          6
#define ETHER_TYPE_LOCATION     12

//IP Header
#define IP_LOCATION             14
#define S_IP_LOCATION           12
#define D_IP_LOCATION           16

#define PROTOCOL_LOCATION       23

//TCP Header
#define TCP_LOCATION            34
#define S_PORT_LOCATION         0
#define D_PORT_LOCATION         2



//ETC
#define TCP_SIZE                20

void print_mac(u_char* mac);
void print_ip(u_char* ip);
void print_port(u_char* port);
void print_tcp_data(u_char* ether_type);
void print_ether_type(u_char* ether_type);
bool check_ether_type_ipv4(u_char* ether_type);
void print_packet_information(struct pcap_pkthdr* header, u_char* packet);
