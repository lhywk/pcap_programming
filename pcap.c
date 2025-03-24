#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>  // MAC 주소 처리
#include <ctype.h>   // isprint 함수 추가

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl : 4, //IP header length
        iph_ver : 4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

/* 패킷을 처리하는 함수*/
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    // Ethernet 헤더 처리
    struct ethheader* eth = (struct ethheader*)packet;

    // Ethernet 타입이 0x0800인 경우만 ( IP 프로토콜 )
    if (ntohs(eth->ether_type) == 0x0800) { 
        // IP 헤더처리
        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        // 프로토콜이 TCP일 경우만 처리
        if (ip->iph_protocol == IPPROTO_TCP) {
            
            // Ethernet 헤더 출력 (출발지 MAC 주소, 목적지 MAC 주소)
            printf("Ethernet Header:\n");
            printf("   Src MAC: %s\n", ether_ntoa((struct ether_addr*)eth->ether_shost));
            printf("   Dst MAC: %s\n", ether_ntoa((struct ether_addr*)eth->ether_dhost));

            // IP 헤더 출력 (출발지 IP 주소, 목적지 IP 주소)
            printf("IP Header:\n");
            printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            // TCP 헤더 출력 (출발지 포트, 목적지 포트)
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));
            printf("TCP Header:\n");
            printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // IP 헤더 길이 및 TCP 헤더 길이 계산
            int ip_header_len = ip->iph_ihl * 4;  
            int tcp_header_len = TH_OFF(tcp) * 4; 

            // 데이터 부분 추출 (TCP 페이로드)
            u_char* data = (u_char*)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
            int data_size = header->len - (data - packet);

            // 메시지 출력 (데이터 내용)
            printf("Message: ");
            int max_length = 100; // 메시지 출력 길이 제한
            for (int i = 0; i < data_size && i < max_length; i++) {
                if (isprint(data[i])) {
                    printf("%c", data[i]); // 인쇄 가능한 문자는 그대로 출력
                }
                else {
                    printf("\\x%02x", data[i]); // 비 ASCII 문자는 16진수로 출력
                }

            }
            if (data_size > max_length) {
                printf("... (메시지 잘림)\n"); // 메시지길이가 너무 길면 잘림 표시
            }
            else {
                printf("\n");
            }
        }
    }
}

int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 캡쳐
    bpf_u_int32 net;

    // 네트워크 인터페이스 열기 (enp0s3 네트워크 인터페이스 사용)
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // 필터 컴파일 (TCP 패킷만 캡처하는 필터 설정)
    pcap_compile(handle, &fp, filter_exp, 0, net);
    
    // 필터 설정 (TCP 패킷 필터)
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // 패킷 캡처 시작 (무한 루프에서 캡처)
    pcap_loop(handle, -1, got_packet, NULL);

    // pcap 핸들 닫기
    pcap_close(handle);  
    return 0;
}
