/* Belkin/Silex flashing utility 
   
   Copyright (c) 2010 Wladimir J. van der Laan

 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use,
 copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following
 conditions:

 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
   
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <linux/if.h>  

// #define NOISY

#define ETH_P_CUSTOM      0x8813

const uint16_t ethertype = ETH_P_CUSTOM;

#define PACKET_BUFFER_SIZE 1536

/* Replies have the same command value, but with 0x80 set */
#define SCMD_REPLY_BIT 0x80

/* Command is 1..20 */
#define SCMD_BROWSEREQ  1
#define SCMD_ADSETREQ   2
#define SCMD_EEPSETREQ  3  /* Erase and rewrite flash memory */
   /* 2b seqence number
         0x0000            erases flash
         0x0001....0xfffe  current seq nr
         0xffff            checks ROM checksum
      returns: 00 83 <2b seqid ACK> <2b seqid ??> ...
   */
#define SCMD_BOOT       4  /* Go out of debug shell, boot OS */
#define SCMD_SET_MEM    10 /* set RAM at address */
   /* 1b subcommand (?)
      4b address 
      4b size
      [data]
      returns: 00 8a (zeroes) 
   */
#define SCMD_FLDP_ERASE 20 /* ???? */

#define FLASH_TRANSFER_SIZE 1024

/* Print a packet nicely in hex */
#define BYTES_PER_LINE 16
void hexdump(const uint8_t *data, size_t size)
{
    for(size_t i=0; i<size; i+=BYTES_PER_LINE)
    {
        printf("%08x ", (unsigned int)i);
        for(size_t j=0; j<BYTES_PER_LINE; ++j)
        {
            if((i+j)<size)
                printf("%02x ", data[i+j]);
            else 
                printf("   ");
        }
        for(size_t j=0; j<BYTES_PER_LINE; ++j)
        {
            if((i+j)<size)
            {
                uint8_t ch = data[i+j];
                if(ch>=32 && ch<128)
                    printf("%c", ch);
                else
                    printf(".");
            } else 
            {
                printf(" ");
            }
        }
        printf("\n");        
    }
    
}

/* state */
int sock;
int sequence_id;
/* local interface index */
int ifindex;
/* ethernet address of interface ifindex */
uint8_t my_phy[6];
/* target address, initially broadcast */
uint8_t tgt_phy[6];
/* last packet receive address */
uint8_t rcv_phy[6];

/* send packet */
void send_packet(uint16_t command, const uint8_t *data, size_t size)
{
    /* Try sending packet */
    struct sockaddr_ll to_host;
    uint8_t packet_out[1536];
    
    memset(&to_host, 0 , sizeof(to_host));
    to_host.sll_family = AF_PACKET;
    to_host.sll_ifindex = ifindex;
    to_host.sll_halen = 6;
    for(int i=0; i<6; ++i)
        to_host.sll_addr[i] = tgt_phy[i];

    /* fill packet */
    for(int i=0; i<6; ++i)
        packet_out[i] = tgt_phy[i];
    for(int i=0; i<6; ++i)
        packet_out[i+6] = my_phy[i]; /* ?? auto filled in? */
    packet_out[12] = ethertype >> 8;
    packet_out[13] = ethertype & 0xFF;
    packet_out[14] = command >> 8;
    packet_out[15] = command & 0xFF;
    
    /* Copy in data */
    assert((size+16)<PACKET_BUFFER_SIZE);
    memcpy(&packet_out[16], data, size);
    
    /* send it */
    if(sendto(sock,packet_out, size+16, 0,
        (const struct sockaddr *)&to_host, sizeof(to_host)) < 0)
    {
        perror("sendto");
        exit(1);
    }
}

/* receive packet 
   data must be able to hold PACKET_BUFFER_SIZE bytes
*/
size_t recv_packet(int16_t *command, uint8_t *data)
{
    uint8_t buffer[PACKET_BUFFER_SIZE];
    struct sockaddr_ll peer_host;
    uint16_t ethtype;
    size_t n, payload_size;

    while(1)
    {
        socklen_t addr_size = sizeof(peer_host);
        n = recvfrom(sock,buffer,PACKET_BUFFER_SIZE,0,(struct sockaddr *)&peer_host,&addr_size);
        
        if(n<16)
        {
            printf("Skipping small packet\n");
            continue;
        }
#ifdef NOISY
        printf("Destination MAC address: "
               "%02x:%02x:%02x:%02x:%02x:%02x\n",
               buffer[0],buffer[1],buffer[2],
               buffer[3],buffer[4],buffer[5]);
        printf("Source MAC address: "
               "%02x:%02x:%02x:%02x:%02x:%02x\n",
               buffer[6],buffer[7],buffer[8],
               buffer[9],buffer[10],buffer[11]);
#endif        
        /* store source address for reference */
        for(int i=0; i<6; ++i)
            rcv_phy[i] = buffer[6 + i];
        ethtype = (buffer[12]<<8)|buffer[13];
#ifdef NOISY
        printf("Ethtype: %04x\n", ethtype);
#endif    
        if(ethtype == ethertype)
            /* TODO: more validation of incoming packets */
            break;
    }
    *command = (buffer[14]<<8)|buffer[15];
#ifdef NOISY
    printf("Reply  : %08x\n", *command);
    printf("Payload: \n");
#endif
    payload_size = n-16;
#ifdef NOISY
    hexdump(buffer+16, payload_size);
#endif
    /* Copy out data */
    memcpy(data, &buffer[16], payload_size);
    
    return payload_size;
}

/* simple buffer appending/reading */
inline void tx_uint16(uint8_t *buf, size_t *ptr, uint16_t val)
{
    buf[(*ptr)++] = val>>8; 
    buf[(*ptr)++] = val;
}
inline void tx_uint32(uint8_t *buf, size_t *ptr, uint32_t val)
{
    buf[(*ptr)++] = val>>24; 
    buf[(*ptr)++] = val>>16;
    buf[(*ptr)++] = val>>8; 
    buf[(*ptr)++] = val;
}
inline uint16_t rx_uint16(const uint8_t *buf, size_t *ptr)
{
    uint16_t val = (buf[(*ptr)+0]<<8)|(buf[(*ptr)+1]); 
    *ptr+=2;
    return val;
}
inline uint32_t rx_uint32(const uint8_t *buf, size_t *ptr)
{
    uint32_t val = (buf[(*ptr)+0]<<24)|(buf[(*ptr)+1]<<16)|(buf[(*ptr)+2]<<8)|(buf[(*ptr)+3]); 
    *ptr+=4;
    return val;
}

/* Compute trivial checksum of a piece of memory */
inline uint16_t compute_checksum(const uint8_t *buf, size_t size)
{
    uint16_t chksum = 0;
    for(int i=0; i<size; ++i)
    {
        chksum += buf[i];
    }
    return chksum;
}

/* the big flash function 
   flash data of memblock at address addr, size memblock_size
   handles the case of memblock_size=0 correctly by doing nothing.
 */
void flash_write(uint32_t addr, const uint8_t *memblock, size_t memblock_size)
{
    size_t memptr = 0;
    size_t ptr;
    uint8_t buffer[PACKET_BUFFER_SIZE];
    size_t rsize;
    uint16_t reply;
    
    while(memptr < memblock_size)
    {
        int osize;
        
        ptr = 0;
        tx_uint16(buffer, &ptr, sequence_id);
        tx_uint32(buffer, &ptr, addr);
        osize = FLASH_TRANSFER_SIZE; /* size of this current block */
        if(osize > (memblock_size - memptr))
            osize = (memblock_size - memptr);
        tx_uint16(buffer, &ptr, osize);

        printf("%08x: Write %04x bytes           \r", addr, osize);

        /* copy data in */
        memcpy(&buffer[ptr], &memblock[memptr], osize);
        ptr += osize; 
        /* add checksum */
        tx_uint16(buffer, &ptr, compute_checksum(&memblock[memptr], osize));
        
        send_packet(SCMD_EEPSETREQ, buffer, ptr);
        
        /* receive reply */
        rsize = recv_packet(&reply, buffer);
        assert(reply == (SCMD_REPLY_BIT|SCMD_EEPSETREQ));

        //hexdump(buffer,rsize);
        
        ptr = 0;
        uint16_t ack_seq = rx_uint16(buffer, &ptr);
        uint16_t nak_seq = rx_uint16(buffer, &ptr); // ?
#ifdef NOISY        
        printf("rv: %04x %04x\n", ack_seq, nak_seq);
#endif
        
        if(ack_seq != sequence_id)
        {
            printf("Sync error (NEQ)");
            exit(1);
        }
        
        addr += osize;
        memptr += osize;
        sequence_id += 1;
        if(sequence_id == 0xffff)
            sequence_id = 1;
    }

}

/* Motorola hex format parsing */
#define MAX_HEX_LINE_SIZE 200
void parse_hex_file(const char *filename)
{
    FILE *f;
    /* we want to collect continuos portions of FLASH_TRANSFER_SIZE bytes or smaller 
     * and send these to the flash function
     */
    uint8_t buffer[FLASH_TRANSFER_SIZE];
    char line[MAX_HEX_LINE_SIZE+1];
    int total = 0;

    f = fopen(filename, "r");
    if(f == NULL)
    {
        fprintf(stderr, "Cannot find HEX input file\n");
        exit(1);
    }
    /* Format (http://en.wikipedia.org/wiki/SREC_%28file_format%29): 
       S3 25 BF923B60 0802184F29F9A74DE1B71D633A65D850D03C1FBD114EC07592D40D5F02FAE8E8 6E
       ...
       S7 05 00000000 FA

       ^^
       S3 Data seqence, 4 address bytes
       S7 End of block, 4 address bytes
          ^^ 
          Number of bytes (including addr and checksum) that follow
          [data]... <checksum>
     */
    uint32_t cur_base_addr = 0; /* base of buffer */
    uint8_t *oaddr;
    int cur_buf_size = 0; /* size of buffer */
    
    while(fgets(line, MAX_HEX_LINE_SIZE, f))
    {
        //printf("%s", line);
        assert(line[0] == 'S');
        int line_size, addr;
        int data_bytes;
        
        sscanf(&line[2], "%02x", &line_size);
        //printf("Line size is %i\n", line_size);
        
        switch(line[1])
        {
        case '3':
            sscanf(&line[4], "%08x", &addr);
            data_bytes = line_size - 1 - 4;
            //printf("Addr is %08x, %02x\n", addr, data_bytes);
            /* check if data can be placed at end of current buffer */
            if(addr == (cur_base_addr+cur_buf_size) && (addr+data_bytes) <= (cur_base_addr+FLASH_TRANSFER_SIZE))
            {
                oaddr = &buffer[cur_buf_size];
                cur_buf_size += data_bytes;
            }
            else /* Flush buffer, start new one */
            {
                //printf("From: %08x\n", cur_base_addr);
                //hexdump(buffer, cur_buf_size);
                flash_write(cur_base_addr, buffer, cur_buf_size);
                total += cur_buf_size;
            
                oaddr = buffer;
                cur_base_addr = addr;
                cur_buf_size = data_bytes;
            }
            /* parse hex bytes */
            for(int i=0; i<data_bytes; ++i)
            {
                int val;
                sscanf(&line[12+2*i], "%02x", &val);
                oaddr[i] = val;
            }
            break;
        case '7': /* end of block - flush buffer */
            //printf("From: %08x\n", cur_base_addr);
            //hexdump(buffer, cur_buf_size);
            flash_write(cur_base_addr, buffer, cur_buf_size);
            total += cur_buf_size;
            
            cur_base_addr = 0;
            cur_buf_size = 0;
            break; 
        default:
            /* Unsupported */
            assert(0);
        }
    }
    fclose(f);
    fprintf(stderr, "\nOK: %i bytes flashed\n", total);
}

int main(int argc, char **argv) {
    int n;
    uint8_t buffer[2048];
    unsigned char *iphead, *ethhead;
    const char *filename;
    const char *interface;
    struct ifreq ifr; 
    
    if(argc<3)
    {
        fprintf(stderr,"Usage: sxflash <eth0> <name>.hex\n");
        fprintf(stderr, "Must specify an interface and Motorola HEX file to flash\n");
        exit(1);
    }
    else
    {
        interface = argv[1];
        filename = argv[2];
    }

    struct sockaddr_ll bind_host;

    if ( (sock=socket(PF_PACKET, SOCK_RAW,
                      htons(ethertype)))<0) { 
        perror("socket");
        exit(1);
    }    
    
    printf("Binding to interface %s\n", interface);

    memset((void *)&ifr, 0, sizeof(ifr));
    strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);

    /* Get interface index */
    if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
    {
        printf("Error getting Interface index !\n");
        exit(1);
    }
    ifindex = ifr.ifr_ifindex;
    printf("Interface index %i\n", ifindex);

    /* Get hardware address */
    if (ioctl (sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("SIOCGIFHWADDR(%s): %m\n", ifr.ifr_name);
        exit(1);
    }
    for(int i=0; i<6; ++i)
        my_phy[i] = ((uint8_t *) &ifr.ifr_hwaddr.sa_data)[i];

    printf("Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n",
      (int) my_phy[0], (int) my_phy[1], (int) my_phy[2],
      (int) my_phy[3], (int) my_phy[4], (int) my_phy[5]);
    
    memset(&bind_host, 0 , sizeof(bind_host));
    bind_host.sll_family = AF_PACKET;
    bind_host.sll_ifindex = ifindex;

    if(bind(sock, (const struct sockaddr *)&bind_host, sizeof(bind_host)) < 0)
    {
        perror("Error binding to interface\n");
        exit(1);
    }
    
    size_t ptr = 0;
    size_t size = 0;
    int16_t reply;

    /* Send browse request to broadcase to find out device MAC addr */
    printf("Sending browse request\n");
    for(int i=0; i<6; ++i)
        tgt_phy[i] = 0xFF;
    send_packet(SCMD_BROWSEREQ, buffer, ptr);
    
    size = recv_packet(&reply, buffer);
    printf("Recived: %04x\n", reply);
    hexdump(buffer,size);

    for(int i=0; i<6; ++i)
        tgt_phy[i] = rcv_phy[i];
    printf("Target   %02x:%02x:%02x:%02x:%02x:%02x\n",
      (int) tgt_phy[0], (int) tgt_phy[1], (int) tgt_phy[2],
      (int) tgt_phy[3], (int) tgt_phy[4], (int) tgt_phy[5]);
    
    /* Start the flashing */
    printf("Clearing flash\n");
    ptr = 0;
    tx_uint16(buffer, &ptr, 0x0000);
    send_packet(SCMD_EEPSETREQ, buffer, ptr);
    
    size = recv_packet(&reply, buffer);
    printf("Recived: %04x\n", reply);
    hexdump(buffer,size);
    
    sequence_id = 1; /* Reset sequence to 1 after reset */

    parse_hex_file(filename);
    
    printf("Success...\n");

    printf("Booting into OS\n");
    send_packet(SCMD_BOOT, NULL, 0);
    size = recv_packet(&reply, buffer);
    printf("Recived: %04x\n", reply);
    hexdump(buffer,size);

}

