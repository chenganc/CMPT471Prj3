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
  uint16_t packetType = ethertype(packet);


  if(packetType == ethertype_ip) {

    /*Case 1 if packet is ip packet / icmp packet*/
      /*Find out if the packet is ip packet or icmp packet*/
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      struct sr_rt * target = NULL;

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
        if(sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst)){
          sr_send_packet(sr,sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst)->mac,ETHER_ADDR_LEN,addr->interface);
        }else{
          printf("%s\n", "No such address");
        }

      }else{
        /*Packet is icmp packet*/
      }


    /*Case 2 if packet is arp packet*/
    }else{
        printf("%s\n", "ARP Packet");
    }
}/* -- sr_handlepacket -- */
