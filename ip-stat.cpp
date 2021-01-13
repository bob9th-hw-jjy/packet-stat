#include "ethernet.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unordered_map>

#define SIZE_ETHERNET 14
using namespace std;

void formatter(pair<struct in_addr, struct packet_info> elem) {
    printf("%16s", inet_ntoa(elem.first));
    printf("%16d", elem.second.Tx_Packets);
    printf("%16d", elem.second.Tx_Bytes);
    printf("%16d", elem.second.Rx_Packets);
    printf("%16d", elem.second.Rx_Bytes);
    cout << endl;
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        printf("syntax : ip-stat <pcap file>\n");
        printf("sample : ip-stat test.pcap\n");
        exit(1);
    }

    const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
    unordered_map<struct in_addr, struct packet_info, ipv4_hash, ipv4_equalto> ipv4_to_packet;
    u_int size_ip;
	u_int size_tcp;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t * pcap = pcap_open_offline(argv[1], errbuf);
    if(nullptr == pcap) {
        printf("Error: pcap_open_offline failed\n");
        exit(1);
    }
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			// printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        
        if(ipv4_to_packet.find(ip->ip_src) == ipv4_to_packet.end()) {
            ipv4_to_packet[ip->ip_src] = (packet_info) { 
                0, 0, 0, 0
            };
        }
        
        ipv4_to_packet[ip->ip_src].Tx_Packets += 1;
        ipv4_to_packet[ip->ip_src].Tx_Bytes += header->caplen;

        if(ipv4_to_packet.find(ip->ip_dst) == ipv4_to_packet.end()) {
            ipv4_to_packet[ip->ip_dst] = (packet_info) { 
                0, 0, 0, 0
            };
        }
        
        ipv4_to_packet[ip->ip_dst].Rx_Packets += 1;
        ipv4_to_packet[ip->ip_dst].Rx_Bytes += header->caplen;
	}
    printf("%80s","--------------------------------------------------------------------------------");
    cout << endl;
    printf("%16s", "IP");
    printf("%16s", "Tx Packets");
    printf("%16s", "Tx Bytes");
    printf("%16s", "Rx Packets");
    printf("%16s", "Rx Bytes");
    cout << endl;
    printf("%80s","--------------------------------------------------------------------------------");
    cout << endl;
    for(auto elem : ipv4_to_packet)
        formatter(elem);

    printf("%80s","--------------------------------------------------------------------------------");
    cout << endl << endl;
	pcap_close(pcap);
}