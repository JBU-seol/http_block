#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <pcap.h>

struct pseudo_hdr{
    struct in_addr saddr;
    struct in_addr daddr;
    uint8_t reserve;
    uint8_t protocol;
    uint16_t len;
    struct libnet_tcp_hdr pse_tcp_hdr;
};

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

unsigned short checksum(unsigned short *buf, int len){
    unsigned long sum = 0;
    while(len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("Only HTTP finding...\n");
        u_char site[100]={0};
        u_char target[]="test.gilgil.net";
        //uint8_t macbuf[6];
        //struct in_addr ipbuf;
        //uint16_t portbuf;
        //uint32_t seqbuf;
        //uint32_t ackbuf;
        struct libnet_ethernet_hdr* ethernet_hdr=(struct libnet_ethernet_hdr*)packet;
        if(ntohs(ethernet_hdr->ether_type)==ETHERTYPE_IP){
            struct libnet_ipv4_hdr* ipv4_hdr=(struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));
            if((ipv4_hdr->ip_p)==IPPROTO_TCP){
                struct libnet_tcp_hdr* tcp_hdr=(struct libnet_tcp_hdr*)((u_char*)ipv4_hdr+(ipv4_hdr->ip_hl<<2));
                if(ntohs(tcp_hdr->th_dport)==80 || ntohs(tcp_hdr->th_sport)==80){


                    unsigned char* http_p=(unsigned char*)((u_char*)tcp_hdr+(tcp_hdr->th_off<<2));
                    uint32_t count=(uint32_t)(ntohs(ipv4_hdr->ip_len)-(ipv4_hdr->ip_hl<<2)-(tcp_hdr->th_off<<2)); // data size

                    if( !( strncmp((char*)http_p,"GET ",4)) ){
                        for(int i=0 ; ; i++){
                            if( !(strncmp((char*)(http_p+i),"Host: ",6)) ){
                                http_p = http_p + i + 6 ;
                                break;
                            }

                        }
                        for(int i=0;;i++){
                            if( *(http_p+i) == 0x0d && *(http_p+i+1) == 0x0a )
                                break;
                            else
                                site[i] = *(http_p+i);
                        }
                    }

                    if( !strncmp((char*)site,(char*)target,sizeof(target))){
                        printf("---------------Find it!--------------------\n\n");
                        printf("site : %s\n",site);
                        //--------------save info---------------------------
                        //uint8_t macbuf[6];
                        //for(int i=0;i<6;i++) macbuf[i]=ethernet_hdr->ether_shost[i];
                        //struct in_addr ipbuf=ipv4_hdr->ip_src;
                        //uint16_t portbuf=tcp_hdr->th_sport;
                        //uint32_t ackbuf=tcp_hdr->th_ack;
                        //uint32_t seqbuf=tcp_hdr->th_seq;
                        //-------------ip_checksum calculate------------------
                        unsigned short* ipp=(unsigned short*)ipv4_hdr;
                        ipv4_hdr->ip_sum=0;
                        ipv4_hdr->ip_len= ntohs(0x36);
                        ipv4_hdr->ip_tos = 0x44;
                        ipv4_hdr->ip_sum=checksum(ipp,sizeof(struct libnet_ipv4_hdr)/sizeof(unsigned short));
                        //-------------checksum calculate----------------------
                        struct pseudo_hdr pse_hdr;
                        pse_hdr.saddr = ipv4_hdr->ip_src;
                        pse_hdr.daddr = ipv4_hdr->ip_dst;
                        pse_hdr.protocol = ipv4_hdr->ip_p;
                        pse_hdr.len = ntohs((uint16_t)(tcp_hdr->th_off <<2));
                        pse_hdr.reserve = 0;
                        tcp_hdr->th_sum = 0;
                        tcp_hdr->th_flags = 0x14;//RST Flag

                        memcpy(&pse_hdr.pse_tcp_hdr,tcp_hdr,sizeof(pse_hdr.pse_tcp_hdr));
                        tcp_hdr->th_sum = checksum((unsigned short*)&pse_hdr,
                                                   sizeof(struct pseudo_hdr)/sizeof(unsigned short));

                        u_char pkt[54]={0};
                        memcpy(pkt,packet,sizeof(pkt));
                        pcap_sendpacket(handle,pkt,sizeof(pkt));


                        /*
                        for(int i=0; i<6; i++) {
                            ethernet_hdr->ether_shost[i] = ethernet_hdr->ether_dhost[i];
                            ethernet_hdr->ether_dhost[i] = macbuf[i];
                        }
                        ipv4_hdr->ip_src.s_addr = ipv4_hdr->ip_dst.s_addr;
                        ipv4_hdr->ip_dst.s_addr = ipbuf.s_addr;
                        tcp_hdr->th_sport = tcp_hdr->th_dport;
                        tcp_hdr->th_dport = portbuf;
                        tcp_hdr->th_ack = tcp_hdr->th_seq;
                        tcp_hdr->th_seq= htonl(ntohl(ackbuf) + count);
                        pse_hdr.saddr = ipv4_hdr->ip_src;
                        pse_hdr.daddr = ipv4_hdr->ip_dst;
                        tcp_hdr->th_sum = 0;
                        tcp_hdr->th_sum = checksum((unsigned short*)&pse_hdr,
                                                   sizeof(struct pseudo_hdr)/sizeof(unsigned short));
                        memcpy(pkt,packet,header->caplen);
                        pcap_sendpacket(handle,pkt,sizeof(pkt));
                        */

                        printf("\n-------------------------------------------\n\n");
                    }

                }

            }
        }
    }

    pcap_close(handle);
    return 0;
}
