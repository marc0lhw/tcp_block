#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>


char* block_message = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Nov 2017 19:00:00 GMT\r\nServer: Apache\r\nContent-Length: 238\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html>\r\n  <head>\r\n    <title>Blcok~!</title>\r\n  </head>\r\n  <body>\r\n   Blocked~! hacked my marc0<p>\r\n  </body>\r\n</html>\r\n";

void usage() {
  printf("syntax: tcp_block <interface>\n");
  printf("sample: tcp_block wlan0\n");
}

int isHttpRequest(const u_char* buf) {
        const char *GET = "GET ";
        const char *POST = "POST ";
        const char *HEAD = "HEAD ";
        const char *PUT = "PUT ";
        const char *DELETE = "DELETE ";
        const char *OPTIONS = "OPTIONS ";
        const char *Host = "Host: ";

        if( memcmp(buf, GET, 4) == 0 || memcmp(buf, PUT, 4) == 0 || memcmp(buf, POST, 5) == 0 ||
        memcmp(buf, HEAD, 5) == 0 || memcmp(buf, DELETE, 7) == 0 || memcmp(buf, OPTIONS, 8) == 0 )
                return 1;
        
        return 0;
}

void printpacket(const u_char * packet){

    	struct libnet_ethernet_hdr* ETH_header;
    	struct libnet_ipv4_hdr* IP_header;
    	struct libnet_tcp_hdr* TCP_header;

	ETH_header = (libnet_ethernet_hdr*)packet;                      // Ethernet 정보 출력
        printf("ETH src : ");
        for(int i = 0; i<6; i++) {
                printf("%02x", ETH_header->ether_shost[i]);
                if(i<5) printf(":");
        }
        printf("\n");
        printf("ETH dst : ");
        for(int i = 0; i<6; i++) {
                printf("%02x", ETH_header->ether_dhost[i]);
                if(i<5) printf(":");
        }
        printf("\n");
        printf("ETH type : %04x ", ntohs(ETH_header->ether_type));
        if(ntohs(ETH_header->ether_type) == 0x0800)                     // IP 일때  진행
                printf("        -> It's IP!\n");
        else printf("\n");


        IP_header = (libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        printf("IP src : %s\n", inet_ntoa(IP_header->ip_src));
        printf("IP dst : %s\n", inet_ntoa(IP_header->ip_dst));
        printf("IP protocol : %02x ", IP_header->ip_p);
        if(IP_header->ip_p == 0x06)                                     // TCP 일때 진행
                printf("        -> It's TCP!\n");
        else printf("\n");
                                                                        // IP 헤더의 len field -> Datalen 구하기
        int Datalen = ntohs(IP_header->ip_len) - sizeof(struct libnet_ipv4_hdr) - sizeof(struct libnet_tcp_hdr);

        TCP_header = (libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

        printf("TCP src : %d\n", ntohs(TCP_header->th_sport));
        printf("TCP dst : %d\n", ntohs(TCP_header->th_dport));
	printf("TCP seq : %ld\n", ntohl(TCP_header->th_seq));
	printf("TCP ack : %ld\n", ntohl(TCP_header->th_ack));
	printf("TCP flags : %02x\n", TCP_header->th_flags);	
	printf("Datalen : %d\n", Datalen);

}

uint16_t checksum(uint8_t *buf, uint16_t len)
{
        uint32_t sum = 0;
	int i=0;

        while(len >1){
                sum += buf[i]<<8 | buf[i+1];
                i+=2;
                len-=2;
        }
        if (len){
                sum += buf[i]<<8 | 0x00;
        }
        while (sum>>16){
		sum = (sum + ( sum>>16 )) & 0xffff;
        }

        return( (uint16_t) sum ^ 0xFFFF);
}

void Tcp_checksum(struct libnet_ethernet_hdr *eth_header, struct libnet_ipv4_hdr *ip4_header, struct libnet_tcp_hdr *tcp_header) {
	uint16_t *p = (uint16_t *)tcp_header;
	uint16_t *tempip;
	uint16_t datalen = ntohs(ip4_header->ip_len) - LIBNET_IPV4_H ;
	uint16_t len = datalen;
	uint32_t chksum = 0;
	len >>= 1;
	tcp_header->th_sum = 0;
	for(int i =0; i<len;i++) {
		chksum += *p++;
	}

	if(datalen % 2 == 1) {
		chksum += *p++ & 0x00ff;
	}
	tempip = (uint16_t *)(&ip4_header->ip_dst);
	for(int i=0;i<2;i++) {
		chksum += *tempip++;
	}
	tempip = (uint16_t *)(&ip4_header->ip_src);
	for(int i=0;i<2;i++) {
		chksum += *tempip++;
	}
	chksum += htons(6);
	chksum += htons(datalen);
	chksum = (chksum >> 16) +(chksum & 0xffff);
	chksum += (chksum >> 16);
	tcp_header->th_sum = (~chksum & 0xffff);
}

int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;
  }

  int Datalen = 0;							// data 존재유무 파악
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    	struct pcap_pkthdr* header;
    	struct libnet_ethernet_hdr* ETH_header;
    	struct libnet_ipv4_hdr* IP_header;
    	struct libnet_tcp_hdr* TCP_header;
    	const u_char* packet;
    	u_char* forward_packet, *backward_packet, *packetdata;
    	int res = pcap_next_ex(handle, &header, &packet);
    	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
    	printf("--------------------[*] %u bytes captured--------------------\n", header->caplen);

	ETH_header = (libnet_ethernet_hdr*)packet;			// Ethernet 정보 출력
	IP_header = (libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
	Datalen = ntohs(IP_header->ip_len) - sizeof(struct libnet_ipv4_hdr) - sizeof(struct libnet_tcp_hdr);
	TCP_header = (libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
	packetdata = (u_char *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr)) ;

	u_int8_t tmp_ether_host[ETHER_ADDR_LEN];
	in_addr tmp_ip_addr;
	u_int16_t tmp_th_port;
	u_int32_t original_th_seq = ntohl(TCP_header->th_seq);
	u_int32_t original_th_ack = ntohl(TCP_header->th_ack);

	if(ntohs(TCP_header->th_dport) == 80 && Datalen > 0 && isHttpRequest(packetdata))				// http packet 이면
	{		
                IP_header->ip_len = 0x2800;                                     // total len : 40
                IP_header->ip_tos = 0x44;
                IP_header->ip_ttl = 0xff;                                       // ttl : 255    
                IP_header->ip_sum = 0;
                IP_header->ip_sum = htons(checksum((uint8_t *)IP_header, sizeof(libnet_ipv4_hdr)));
                TCP_header->th_flags = TH_ACK + TH_RST;
                TCP_header->th_seq = htonl(original_th_seq + 1) ;
                TCP_header->th_win = 0x00;
                TCP_header->th_off = 0x5;                                       // header len : 20
                Tcp_checksum(ETH_header, IP_header, TCP_header);

		printf("-----------------send HTTP forward packet!!!-----------------\n");
//		printpacket(packet);

		if(pcap_sendpacket(handle, packet, 0x36))             // send packet
        	{
                	fprintf(stderr, "\nError sending the packet\n");
                	return -1;
        	}
//		printf("-------------------------------------------------------------\n");

		// Make fake packet with block message
		void *blocked_packet = malloc(sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + strlen(block_message));

		memcpy(tmp_ether_host, ETH_header->ether_dhost, sizeof(tmp_ether_host));
                memcpy(ETH_header->ether_dhost, ETH_header->ether_shost, sizeof(tmp_ether_host));
                memcpy(ETH_header->ether_shost, tmp_ether_host, sizeof(tmp_ether_host));

		tmp_ip_addr = IP_header->ip_src;
		IP_header->ip_src = IP_header->ip_dst;
		IP_header->ip_dst = tmp_ip_addr;

		tmp_th_port = TCP_header->th_sport;
		TCP_header->th_sport = TCP_header->th_dport;
		TCP_header->th_dport = tmp_th_port;

                TCP_header->th_seq = htonl(original_th_ack);
                TCP_header->th_ack = htonl(original_th_seq + Datalen);
		TCP_header->th_flags = TH_ACK + TH_FIN;

                IP_header->ip_len = htons(40 + strlen(block_message));     	// total len : 40 + messagelen
                IP_header->ip_sum = 0;
                IP_header->ip_sum = htons(checksum((uint8_t *)IP_header, sizeof(libnet_ipv4_hdr)));
                Tcp_checksum(ETH_header, IP_header, TCP_header);

		memcpy(blocked_packet, packet, sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
		memcpy(blocked_packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr), block_message, strlen(block_message));

		printf("-----------------send HTTP backward packet!!-----------------\n");
//                printpacket(packet);

		if(pcap_sendpacket(handle, (const u_char*)blocked_packet, 0x36 + strlen(block_message)))             // send packet
                {
                        fprintf(stderr, "\nError sending the packet\n");
                        return -1;
                }
//		printf("-------------------------------------------------------------\n");

		free(blocked_packet);
	}
	else{									// tcp packet 이면
	
		IP_header->ip_len = 0x2800;					// total len : 40
		IP_header->ip_tos = 0x44;
		IP_header->ip_ttl = 0xff;					// ttl : 255	
		IP_header->ip_sum = 0;
		IP_header->ip_sum = htons(checksum((uint8_t *)IP_header, sizeof(libnet_ipv4_hdr)));
		TCP_header->th_flags = TH_ACK + TH_RST;
		TCP_header->th_seq = htonl(original_th_seq + 1) ;
		TCP_header->th_win = 0x00;
		TCP_header->th_off = 0x5;					// header len : 20
		Tcp_checksum(ETH_header, IP_header, TCP_header);

		printf("-----------------send TCP forward packet!!!!-----------------\n");
//		printpacket(packet);
		if(pcap_sendpacket(handle, packet, 0x36))             		// send packet
        	{
                	fprintf(stderr, "\nError sending the packet\n");
                	return -1;
        	}
//		printf("-------------------------------------------------------------\n");

		memcpy(tmp_ether_host, ETH_header->ether_dhost, sizeof(tmp_ether_host));
                memcpy(ETH_header->ether_dhost, ETH_header->ether_shost, sizeof(tmp_ether_host));
                memcpy(ETH_header->ether_shost, tmp_ether_host, sizeof(tmp_ether_host));

                tmp_ip_addr = IP_header->ip_src;
                IP_header->ip_src = IP_header->ip_dst;
                IP_header->ip_dst = tmp_ip_addr;

                tmp_th_port = TCP_header->th_sport;
                TCP_header->th_sport = TCP_header->th_dport;
                TCP_header->th_dport = tmp_th_port;

		TCP_header->th_seq = htonl(original_th_ack);
                TCP_header->th_ack = htonl(original_th_seq + 1);

		printf("-----------------send TCP backward packet!!!-----------------\n");
//		printpacket(packet);

		if(pcap_sendpacket(handle, packet, 0x36))             		// send packet
        	{
                	fprintf(stderr, "\nError sending the packet\n");
                	return -1;
        	}
//		printf("-------------------------------------------------------------\n");
	}
	printf("\n");
  }
  pcap_close(handle);
  return 0;
}

