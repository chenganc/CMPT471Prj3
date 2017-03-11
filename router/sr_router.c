/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* Sherlock */
/* Send arp sneds arps out needs type request/reply given and destination IP and address */
void send_arp(
  struct sr_instance * sr,
  enum sr_arp_opcode arp_opcode,
  char * interface,
  unsigned char * target_hardware_addr,
  uint32_t target_ip_addr
){

}


/* Try and send packet otherwise queue it */
void try_sending(
  struct sr_instance * sr,
  uint32_t d_ip, /* destination ip */
  uint8_t * frame, /* Ethernet frame */
  unsigned int len_frame,
  char * interface
){

}

/* arp_handler by Sherlock */

void arp_handler(
  struct sr_instance * sr,
  struct sr_arp_hdr * packet/* lent */,
  unsigned int len,
  char* interface/* lent */
){

  struct sr_if * receive_interface = sr_get_interface(sr, interface);
  struct sr_arpreq * arp_request;
  struct sr_packet * request_packet;
  unsigned char * packet_sender_hardware_address;
  packet_sender_hardware_addr = packet->ar_sha;
  uint32_t * packet_sender_ip;
  packet_sender_ip_addr = packet->ar_sip;

  if (receive_interface->ip != packet->ar_tip){
    printf("This packet is not for me\n");
    return;
  }
  else{

    /* First check if arp enrty already in my table, if it isn't add it into the cache */

    if (sr_arpcache_lookup(&(sr->cache), packet->ar_sip) == 0){

      arp_request = sr_arpcache_insert(&(sr->cache), packet_sender_hardware_addr, packet_sender_ip_addr);
      request_packet = arp_request->packets;
      while(request_packet!=0){
        try_sending(sr, arp_request->ip, request_packet->buf, request_packet->len, request_packet->iface);
        request_packet = request_packet->next;
      }

      /* Now check if arp is a request and if it is, send a reply */
      if (ntohs(packet->ar_op) == arp_op_request){

        send_arp(sr, arp_op_reply, interface, packet_sender_hardware_addr, packet_sender_ip_addr);
      }

    }
  }



  /* Else -- this is a reply and I don't need to do anything */

}

/* end arp_handler */









/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Cheng */
  /* pseudo-code from sr_arpcache.h is as follows:

  if difftime (now, req->sent) > 1.0
    if req->times_sent >= 5:
      send icmp host unreachable to source addr of all pkts waiting on this request
      arpreq_destroy
    else:
      send arp request
      req->sent = now
      req->times_sent++
  */

  time_t now;
  time(&now);

  /*or time_t now = time(NULL);*/

  struct sr_arpcache *sr_cache = &(sr->cache);

  if(difftime(now, req->sent) > 1.0){

      if(req->times_sent >= 5){
        /*send icmp host unreachable to source addr of all pkts waiting on this request*/
        sr_arpreq_destroy(sr_cache, req);
      }else{
        /*send arp request*/
        req->sent = now;
        req->times_sent++;
      }
  }

}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* TODO: Add forwarding logic here */
  /*Cheng*/

  /*Printing header*/
  print_hdrs(packet, len);

  /*Reading packet type*/

  struct sr_ip_hdr *ip_hdr;

  struct sr_rt *target;

  switch(ethertype(packet)){

    /*Case 1 if packet is ip packet / icmp packet*/
    case ethertype_ip:

      /*Find out if the packet is ip packet or icmp packet*/
      ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
      target = NULL;
      /*Try to match ip dest with the routing table in sr*/
      struct sr_rt* addr = sr->routing_table;
      while(addr != NULL){
        if(addr->dest.s_addr == (addr->mask.s_addr & ip_hdr->ip_dst)){
          target = addr;
        }
        addr = addr->next;
      }

      if(target != NULL){
        /*Packet is ip packet and has matching address from routing table*/

        /*Trying sending ip packet*/
        if(sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst) == 0){
          sr_send_packet(sr,sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst)->mac,ETHER_ADDR_LEN,addr->interface);
        }else{
          printf("%s\n", "No such address");
        }

      }else{
        /*Packet is icmp packet*/
      }


    /*Case 2 if packet is arp packet*/
    case ethertype_arp:
        printf("%s\n", "Case 2 ARP Packet");
        arp_handler(sr, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), (len - sizeof(sr_ethernet_hdr_t)), interface);

  }

}/* -- sr_handlepacket -- */

/* icmp_sender by Cheng */

void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, uint8_t type, unsigned int len, uint8_t code){
        int icmp_len = sizeof(sr_icmp_t3_hdr_t);
        struct sr_icmp_t3_hdr *icmp = calloc(1,icmp_len);
        memcpy(icmp->data, data, len);
        icmp->icmp_type = type;
        icmp->icmp_code = code;
        icmp->icmp_sum = 0;
        int cksum = cksum(icmp, icmp_len);
        if (cksum != 0){
          icmp->icmp_sum = cksum;
        }else{
          icmp->icmp_sum = 0;
        }


}

/* end icmp_sender */
