#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>

/* linked list with ip <-> ethernet MAC entries form /etc/ethers */
struct ethers_ip_ll {
    struct ethers_ip_ll *next;
    uint32_t ip;
    u_char mac[ETH_ALEN];
};

/* for the sake of clarity we'll use globals for a few things */
char *device;       /* device to sniff on */
int verbose = 0;    /* verbose output about device */
pcap_t *handle;     /* handle for the opened pcap session */
struct ethers_ip_ll *ptr_ethip_ll, my_ethers_ip;

/* gracefully handle a Control C */
void ctrl_c(int)
{
    printf("Exiting\n");
    pcap_breakloop(handle);  /* tell pcap_loop or pcap_dispatch to stop capturing */
    pcap_close(handle);
    exit(0);
}

/* usage */
void usage(char *name)
{
    printf("%s - simple ARP sniffer\n", name);
    printf("Usage: %s [-i interface] [-l] [-v]\n", name);
    printf("    -i    interface to sniff on\n");
    printf("    -l    list available interfaces\n");
    printf("    -v    print verbose info\n\n");
    exit(1);
}

/* parse device struct from pcap_findalldevs() */
int parse_device(struct pcap_addr *adptr, struct ethers_ip_ll *myptr)
{
    struct sockaddr *addr;
    struct sockaddr_ll *pktaddr;
    struct sockaddr_in *ipaddr;
    int flag_mac = 0, flag_ip = 0;

    while ((adptr != NULL) && ((flag_mac == 0) || (flag_ip == 0)))
    {
        addr = adptr->addr;
        if ((addr->sa_family == AF_PACKET) && (flag_mac == 0))
        {
            pktaddr = (struct sockaddr_ll *) addr;
            for (int i = 0; i < pktaddr->sll_halen; i++)
            {
                myptr->mac[i] = (u_char) pktaddr->sll_addr[i];
            }
            flag_mac = 1;
        }
        else if ((addr->sa_family == AF_INET) && (flag_ip == 0))
        {
            ipaddr = (struct sockaddr_in *) addr;
            myptr->ip =  (uint32_t) ipaddr->sin_addr.s_addr;
            flag_ip = 1;
        }
        adptr = adptr->next;
    }

    if (verbose)
    {
        printf("host %08x %02x:%02x:%02x:%02x:%02x:%02x\n", myptr->ip,
            myptr->mac[0], myptr->mac[1], myptr->mac[2],
            myptr->mac[3], myptr->mac[4], myptr->mac[5]);
    }

    return ((flag_mac == 1 && flag_ip == 1) ? 0 : -1);
}

/* reads ip and ethernet-MAC entries from file */
int parse_ethers(struct ethers_ip_ll **dllptr, const char *filename)
{
    char *line = NULL;
    char hostname[256];
    size_t len = 0;
    ssize_t read;
    struct ether_addr mac;
    struct in_addr ip;
    struct ethers_ip_ll *dummy, *llptr;
    int found = 0;

    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Cannot open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    /* reset global linked list pointer, but check if there are still entries */
    /* if there are, free them... */
    llptr = *dllptr;

    while (llptr != NULL)
    {
        dummy = llptr->next;
        free(llptr);
        llptr = dummy;
    }

    while ((read = getline(&line, &len, fp)) != -1)
    {
        /* parse a line containing ethernet and hostname entries */
        if (ether_line(line, &mac, hostname) == 0)
        {
            /* convert hostname string to 32bit integer */
            inet_aton(hostname, &ip);

            /* allocate entry */
            dummy = (struct ethers_ip_ll *) malloc(sizeof(struct ethers_ip_ll));
            dummy->next = llptr;

            /* fill the ethernet member */
            for (int i = 0; i < ETH_ALEN; i++)
            {
                dummy->mac[i] = mac.ether_addr_octet[i];
            }

            /* Leave the representation of the ip address to a 32 bit integer. */
            /* This makes it much more convenient to search for a host. */
            /* Note that this number is big-endian, but that doesn't really */
            /* matter when comparing addresses. */
            dummy->ip = ip.s_addr;

            /* update the linked list next pointer */
            llptr = dummy;

            if (verbose)
            {
                printf("entry %08x %02x:%02x:%02x:%02x:%02x:%02x\n", dummy->ip,
                    dummy->mac[0], dummy->mac[1], dummy->mac[2],
                    dummy->mac[3], dummy->mac[4], dummy->mac[5]);
            }

            found++;
        }
    }

    /* update the pointer */
    *dllptr = llptr;

    if (line)
        free(line);

    fclose(fp);

    return found;
}

/* callback function to process a packet when captured */
void process_packet(u_char *user, const struct pcap_pkthdr *header,
    const u_char *packet)
{
    struct ether_header *eth_header;  /* in ethernet.h included by if_eth.h */
    struct ether_arp *arp_packet;     /* from if_eth.h */
    char errbuf[PCAP_ERRBUF_SIZE];

    eth_header = (struct ether_header *) packet;

    /* Only look at ARP messages... */
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP)
        return;

    arp_packet = (struct ether_arp *) (packet + ETH_HLEN);
    
    /* Only look at requests... */
    if (ntohs(arp_packet->arp_op) != ARPOP_REQUEST)
        return;

    if ((arp_packet->arp_tpa[0] == 192) &&
        (arp_packet->arp_tpa[1] == 168) &&
        (arp_packet->arp_tpa[2] == 178) &&
        (arp_packet->arp_tpa[3] == 10))
    {
        printf("ARP to thule detected.\n");
        
        pcap_t *reply;
        const u_char reply_packet[42];
        struct ether_header *eth_reply_header = (struct ether_header *) reply_packet;
        struct ether_arp *arp_reply_packet = (struct ether_arp *) (reply_packet + ETH_HLEN);

        for (int i = 0; i < ETH_ALEN; i++)
        {
            eth_reply_header->ether_dhost[i] = eth_header->ether_shost[i];
        }
        eth_reply_header->ether_shost[0] = 0x2c;
        eth_reply_header->ether_shost[1] = 0xf0;
        eth_reply_header->ether_shost[2] = 0x5d;
        eth_reply_header->ether_shost[3] = 0x3b;
        eth_reply_header->ether_shost[4] = 0xd0;
        eth_reply_header->ether_shost[5] = 0xce;

        eth_reply_header->ether_type = htons(ETHERTYPE_ARP);

        arp_reply_packet->arp_hrd = htons(ARPHRD_ETHER);
        arp_reply_packet->arp_pro = htons(ETHERTYPE_IP);
        arp_reply_packet->arp_hln = ETH_ALEN;
        arp_reply_packet->arp_pln = 4;
        arp_reply_packet->arp_op = htons(ARPOP_REPLY);
        for (int i = 0; i < 4; i++)
        {
            arp_reply_packet->arp_spa[i] = arp_packet->arp_tpa[i];
            arp_reply_packet->arp_tpa[i] = arp_packet->arp_spa[i];
        }

        /* rhea (192.168.178.8) has MAC address 2c:f0:5d:3b:d0:ce */
        arp_reply_packet->arp_tha[0] = 0x2c;
        arp_reply_packet->arp_tha[1] = 0xf0;
        arp_reply_packet->arp_tha[2] = 0x5d;
        arp_reply_packet->arp_tha[3] = 0x3b;
        arp_reply_packet->arp_tha[4] = 0xd0;
        arp_reply_packet->arp_tha[5] = 0xce;

        /* thule (192.168.178.10) has MAC address 5c:f9:dd:76:8a:e6 */
        arp_reply_packet->arp_sha[0] = 0x5c;
        arp_reply_packet->arp_sha[1] = 0xf9;
        arp_reply_packet->arp_sha[2] = 0xdd;
        arp_reply_packet->arp_sha[3] = 0x76;
        arp_reply_packet->arp_sha[4] = 0x8a;
        arp_reply_packet->arp_sha[5] = 0xe6;
        
        if (verbose)
        {
        printf("ARP Reply Source: %d.%d.%d.%d\t\tDestination: %d.%d.%d.%d\n",
            arp_reply_packet->arp_spa[0],
            arp_reply_packet->arp_spa[1],
            arp_reply_packet->arp_spa[2],
            arp_reply_packet->arp_spa[3],
            arp_reply_packet->arp_tpa[0],
            arp_reply_packet->arp_tpa[1],
            arp_reply_packet->arp_tpa[2],
            arp_reply_packet->arp_tpa[3]);

        printf("    src MAC: %02x:%02x:%02x:%02x:%02x:%02x\tdst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_reply_packet->arp_sha[0],
            arp_reply_packet->arp_sha[1],
            arp_reply_packet->arp_sha[2],
            arp_reply_packet->arp_sha[3],
            arp_reply_packet->arp_sha[4],
            arp_reply_packet->arp_sha[5],
            arp_reply_packet->arp_tha[0],
            arp_reply_packet->arp_tha[1],
            arp_reply_packet->arp_tha[2],
            arp_reply_packet->arp_tha[3],
            arp_reply_packet->arp_tha[4],
            arp_reply_packet->arp_tha[5]);
        }
        /* set errbuf to 0 length string to check for warnings */
        errbuf[0] = 0;

        /* open device for sniffing */
        reply = pcap_open_live(device,  /* device to sniff on */
            42,  /* maximum number of bytes to capture per packet */
            PCAP_OPENFLAG_PROMISCUOUS, /* promisc - 1 to set card in promiscuous mode, 0 to not */
            500, /* to_ms - amount of time to perform packet capture in milliseconds */
            errbuf); /* error message buffer if something goes wrong */

        if (reply == NULL)   /* there was an error */
        {
            fprintf(stderr, "%s", errbuf);
            exit(1);
        }

        if (strlen(errbuf) > 0)
        {
            fprintf(stderr, "Warning: %s", errbuf);  /* a warning was generated */
            errbuf[0] = 0;    /* re-set error buffer */
        }
        
        if (pcap_sendpacket(reply, reply_packet, 42) < 0)
        {
            fprintf(stderr, "%s", errbuf);
            exit(1);
        }

        /* close our devices */
        pcap_close(reply);
    }
}

int main(int argc, char *argv[])
{
    char o;                         /* for option processing */
    char errbuf[PCAP_ERRBUF_SIZE];  /* pcap error messages buffer */
    bpf_u_int32 netp;               /* ip address of interface */
    bpf_u_int32 maskp;              /* subnet mask of interface */
    char *filter = "arp";           /* filter for BPF (human readable) */
    struct bpf_program fp;          /* compiled BPF filter */
    int r;                          /* generic return value */
    pcap_if_t *alldevsp;            /* list of interfaces */
    struct pcap_addr *addresses;

    while ((o = getopt(argc, argv, "i:vl")) > 0)
    {
        switch (o)
        {
            case 'i':
                device = optarg;
                break;
            case 'l':
                if (pcap_findalldevs(&alldevsp, errbuf) < 0)
                {
                    fprintf(stderr, "%s", errbuf);
                    exit(1);
                }
                while (alldevsp != NULL)
                {
                    printf("%s\n", alldevsp->name);
                    alldevsp = alldevsp->next;
                }
                exit(0);
            case 'v':
                verbose = 1;
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    /* setup signal handler so Control-C will gracefully exit */
    signal(SIGINT, ctrl_c);

    /* find device for sniffing if needed */
    if (device == NULL)   /* if user hasn't specified a device */
    {
        if (pcap_findalldevs(&alldevsp, errbuf) == -1)
        {
            fprintf(stderr, "error finding devices");
            exit(1);
        }
        device = alldevsp->name; /* let pcap find a compatible device */
        if (device == NULL) /* there was an error */
        {
            fprintf(stderr, "%s", errbuf);
            exit(1);
        }
    }

    addresses = alldevsp->addresses;
    if (parse_device(addresses, &my_ethers_ip) != 0)
    {
            fprintf(stderr, "parsing host ip and mac failed\n");
            exit(1);
    }

    if (parse_ethers(&ptr_ethip_ll, "/etc/ethers") == 0)
    {
            fprintf(stderr, "no usable entries in ether file\n");
            exit(1);
    }

    /* set errbuf to 0 length string to check for warnings */
    errbuf[0] = 0;

    /* open device for sniffing */
    handle = pcap_open_live(device,  /* device to sniff on */
         64,  /* maximum number of bytes to capture per packet */
         PCAP_OPENFLAG_PROMISCUOUS, /* promisc - 1 to set card in promiscuous mode, 0 to not */
         500, /* to_ms - amount of time to perform packet capture in milliseconds */

         errbuf); /* error message buffer if something goes wrong */

    if (handle == NULL)   /* there was an error */
    {
        fprintf(stderr, "%s", errbuf);
        exit(1);
    }

    if (strlen(errbuf) > 0)
    {
        fprintf(stderr, "Warning: %s", errbuf);  /* a warning was generated */
        errbuf[0] = 0;    /* re-set error buffer */
    }

    if (verbose)
    {
        printf("Using device: %s\n", device);
        /* printf("Using libpcap version %s", pcap_lib_version); */
    }
    /* find out the datalink type of the connection */
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "This program only supports Ethernet cards!\n");
        exit(1);
    }

    /* get the IP subnet mask of the device, so we set a filter on it */
    if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1)
    {
        fprintf(stderr, "%s", errbuf);
        exit(1);
    }

    /* compile the filter, so we can capture only stuff we are interested in */
    if (pcap_compile(handle, &fp, filter, 0, maskp) == -1)
    {
        fprintf(stderr, "%s", pcap_geterr(handle));
        exit(1);
    }

    /* set the filter for the device we have opened */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "%s", pcap_geterr(handle));
        exit(1);
    }

    /* we'll be nice and free the memory used for the compiled filter */
    pcap_freecode(&fp);

    if ((r = pcap_loop(handle, -1, process_packet, NULL)) < 0)
    {
        if (r == -1)    /* pcap error */
        {
            fprintf(stderr, "%s", pcap_geterr(handle));
            exit(1);
        }
        /* otherwise return should be -2, meaning pcap_breakloop has been called */
    }

    /* close our devices */
    pcap_close(handle);
}
