#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/if_ether.h>

/* for the sake of clarity we'll use globals for a few things */
char *device;       /* device to sniff on */
int verbose = 0;    /* verbose output about device */
pcap_t *handle;     /* handle for the opened pcap session */

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

/* callback function to process a packet when captured */
void process_packet(u_char *user, const struct pcap_pkthdr *header,
    const u_char * packet)
{
    struct ether_header *eth_header;  /* in ethernet.h included by if_eth.h */
    struct ether_arp *arp_packet; /* from if_eth.h */
    char *op;
    char errbuf[PCAP_ERRBUF_SIZE];
    int r;

    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP)
        return;

    arp_packet = (struct ether_arp *) (packet + ETH_HLEN);
    
    if (ntohs(arp_packet->arp_op) != ARPOP_REQUEST)
        return;

    if ((arp_packet->arp_tpa[0] == 192) &&
        (arp_packet->arp_tpa[1] == 168) &&
        (arp_packet->arp_tpa[2] == 178) &&
        (arp_packet->arp_tpa[3] == 10))
    {
        printf("ARP to thule detected.\n");
        
        pcap_t * reply;
        const u_char reply_packet[42];
        struct ether_header *eth_reply_header = (struct ether_header *) reply_packet;
        struct ether_arp *arp_reply_packet = (struct ether_arp *) (reply_packet + ETH_HLEN);

        for (int i; i < ETH_ALEN; i++)
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
        for (int i; i < 4; i++)
        {
            arp_reply_packet->arp_spa[i] = arp_packet->arp_tpa[i];
            arp_reply_packet->arp_tpa[i] = arp_packet->arp_spa[i];
        }
        eth_reply_header->ether_type = htons(ETHERTYPE_ARP);

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
    struct pcap_pkthdr header;      /* packet header from pcap */
    const u_char *packet;           /* packet */
    bpf_u_int32 netp;               /* ip address of interface */
    bpf_u_int32 maskp;              /* subnet mask of interface */
    char *filter = "arp";           /* filter for BPF (human readable) */
    struct bpf_program fp;          /* compiled BPF filter */
    int r;                          /* generic return value */
    pcap_if_t *alldevsp;            /* list of interfaces */

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
