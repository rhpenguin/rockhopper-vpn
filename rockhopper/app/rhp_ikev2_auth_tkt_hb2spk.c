/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <sys/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_vpn.h"
#include "rhp_ikev2.h"
#include "rhp_forward.h"
#include "rhp_eap.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_http.h"
#include "rhp_radius_impl.h"
#include "rhp_nhrp.h"

/*

 - IKEv2 Authentication Ticket - Rockhopper's Private extension

    IKEv2 Authentication Ticket Notification is for spoke-to-spoke
    mutual-authentication to simply implement a Single Sign-On
    property for a dynamic shortcut tunnel.

     - [e.g.] A simple and light-weight distributed authentication
              method for DMVPN spoke nodes which establish a shortcut
              VPN connection.

     - [cf.] A basic idea: A Kerberos ticket or an IKEv2 session
             resumption's ticket.



                                Hub (Authenticator and Ticket issuer)
                                 |
                   +-------------+-------------+
                   |                           |
                   |                           |
                   |                           |
                   |                           |
      Shortcut-responder =================== Shortcut-initiator
                  Spoke-to-Spoke (shortcut) tunnel



        0                     1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         TKT_ATTR_TYPE         |       TKT_ATTR_SUB_TYPE       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |        TKT_ATTR_LENGTH        |                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
       |                                                               |
       ~                Ticket's attribute Value                       ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 1: RHP_AUTH_TICKET_ATTRIBUTE structure



        0                     1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  Reserved   |        Payload Length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Protocol ID(=0)| SPI Size(=0)  |  Notify Message Type(59309)   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | AUTH_TKT_TYPE |    Reserved   |     AUTH_TKT_ATTRIBUTE_NUM    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~       Ticket's attributes (RHP_AUTH_TICKET_ATTRIBUTEs)        ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 2: RHP_AUTH_TICKET Notify Payload



                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |Protocol ID(=0)| SPI Size(=0)  |  Notify Message Type(59310)   |
 (*a1)+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                   Shortcut-responder spoke                    !
      !                     node's SPI (IKE SA)                       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                     Initialization Vector                     !
      !         (length is block size for encryption algorithm)       !
 (*e1)+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | AUTH_TKT_TYPE |    Reserved   |     AUTH_TKT_ATTRIBUTE_NUM    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
       ~       Ticket's attributes (RHP_AUTH_TICKET_ATTRIBUTEs)        ~
      |                                                               |
      +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !               !             Padding (0-255 octets)            !
      +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
      !                                               !  Pad Length   !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+(*e2)
      ~                    Integrity Checksum Data                    ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+(*a2)

                  Figure 3: RHP_ENC_AUTH_TICKET Notify Payload


    Notify Message Type:

       - RHP_AUTH_TICKET(59309): Exchanged between a hub (Authenticator)
          node and a shortcut-initiator spoke node when the initiator spoke
          node starts a dynamic spoke-to-spoke (shortcut) tunnel.


       - RHP_ENC_AUTH_TICKET(59310):
       	 	First, exchanged between a hub (Authenticator) node and a shortcut
       	 	-initiator spoke node.
       	 	The initiator node will forward this payload to a shortcut-responder
       	 	spoke node when starting to connect a dynamic spoke-to-spoke (shortcut)
       	 	tunnel. The Enc and Integ scheme of this payload is almost the same
       	 	as an IKEv2 E payload.

       	 	Encrypted fields: From (*e1) to (*e2)
       	 	Integrity-checked fields: From (*a1) to (*a2). Integrity Checksum Data
       	 	field is cleared with zeros before the checksum value is calculated.

				  Initialization Vector is secure-randomly generated value.

          Enc and Integ Algorithms are the same as the IKE SA between the hub node
          and the shortcut-responder spoke node. The keys are generated like this:

				- SK_dmvpn_a: An Integ key
				- SK_dmvpn_e: An Enc key

				  {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | SK_dmvpn_a | SK_dmvpn_e}
           = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr )

         [See also RFC5996 2.14. Generating Keying Material for the IKE SA.]


        Therefore, the shortcut-initiator spoke node, which is going to forwarding
        this payload, will never know the shortcut-responder spoke node's key value
        to decrypt this payload. The hub node and the shortcut-responder node only
        know the value to encrypt/decrypt this payload.


       - RHP_AUTH_TICKET_SUPPORTED(59311): Exchanged between a hub (Authenticator)
          node and a shortcut-initiator/responder spoke node to signal support for
          Authenticatin Ticket. The notification payload for each peer is included
          in the IKE_AUTH message. The notification data field is left empty.


    Shortcut-responder spoke node's IKE_SA SPI (8 bytes):
       This can be used by shortcut-responder spoke node as a hint for the key
       index to decrypt the RHP_ENC_AUTH_TICKET payload issued by hub (Authenticator)
       node and forwarded via the shortcut-initiator spoke node. In conformity
       with an IKEv2 Notify payload (RFC5996), Protocol ID and SPI Size fields are
       set to zero.



    AUTH_TKT_TYPE:
       - TICKET_NONE(0)      : Not used.
       - TICKET_REQUEST(1)   : A shortcut-initiator ==> A hub (Authenticator).
       - TICKET_RESPONSE(2)  : A hub (Authenticator) ==> A shortcut-initiator.
       - TICKET_FORWARD(3)   : From a hub (Authenticator) ==> Via a shortcut-initiator
                               ==> To a shortcut-responder.
       - TICKET_ERROR(4)     : For RHP_AUTH_TICKET.
                               A hub (Authenticator) ==> A shortcut-initiator.



    AUTH_TKT_ATTRIBUTE_NUM:
       The num of attribute sctructures (RHP_AUTH_TICKET_ATTRIBUTEs).



		TKT_ATTR_TYPE [RHP_AUTH_TICKET_ATTRIBUTE]:

			 - A hub (Authenticator) node ID(1):
			    * TKT_ATTR_SUB_TYPE: IKEv2's ID Type (RFC5996 3.5. Identification Payloads).
			    * Value: An IKEv2's ID.

			 - A shortcut-initiator spoke node ID(2):
			    * TKT_ATTR_SUB_TYPE: IKEv2's ID Type (RFC5996 3.5. Identification Payloads).
			    * Value: An IKEv2's ID.

			 - A shortcut-responder spoke node ID(3):
			    * TKT_ATTR_SUB_TYPE: IKEv2's ID Type (RFC5996 3.5. Identification Payloads).
			    * Value: An IKEv2's ID.

       - A public IP for a shortcut-initiator spoke node(4):
			    * TKT_ATTR_SUB_TYPE: IPv4(4) or IPv6(6)
			    * Value: A public IPv4 address(4 bytes) or IPv6 address(16 bytes).
			            [i.e. NHRP/DMVPN: A NBMA address]

       - A public IP for a shortcut-responder spoke node(5):
			    * TKT_ATTR_SUB_TYPE: IPv4(4) or IPv6(6)
			    * Value: A public IPv4 address(4 bytes) or IPv6 address(16 bytes).
			             [i.e. NHRP/DMVPN: A NBMA address]

       - An internal IP for a shortcut-initiator spoke node(6): [Currently, Not used.]
			    * TKT_ATTR_SUB_TYPE: IPv4(4) or IPv6(6)
			    * Value: An internal IPv4 address(4 bytes) or IPv6 address(16 bytes).
			             [i.e. NHRP/DMVPN: A protocol address]

       - An internal IP for a shortcut-responder spoke node(7):
			    * TKT_ATTR_SUB_TYPE: IPv4(4) or IPv6(6)
			    * Value: An internal IPv4 address(4 bytes) or IPv6 address(16 bytes).
			             [i.e. NHRP/DMVPN: A protocol address]

       - A time of ticket's expiration(8):
			    * TKT_ATTR_SUB_TYPE: Not used. It must be zero.
			    * Value: Unix Epoc time (int64_t[64bits]). By default, the value is
			             300 seconds.

       - A session key shared between shortcut-spoke nodes(9):
			    * TKT_ATTR_SUB_TYPE: Not used. It must be zero.
			    * Value: A format and a usage method are the same as IKEv2 PSK Authentication.
                   It must be randomly and securely generated and the min length is
                   16 bytes. The default length is 64 bytes.



    TKT_ATTR_LENGTH [RHP_AUTH_TICKET_ATTRIBUTE]:
      	An attribute structure's length including the header fields (TKT_ATTR_TYPE +
      	TKT_ATTR_SUB_TYPE + TKT_ATTR_LENGTH).




  - Exchanges and Payloads


	(0) IKE_AUTH Exchange between a hub (Authenticator) node and a shortcut-initiator/responder
      spoke node which connect a dynamic spoke-to-spoke (shortcut) tunnel.

   [Shortcut-initiator/resonponder spoke node]
			 request             --> IDi, [CERT+],
															 [N+],
															 [IDr],
															 AUTH(PSK),
															 [CP(CFG_REQUEST)],
															 [N(RHP_AUTH_TICKET_SUPPORTED)]
															 [N+],
															 SA, TSi, TSr,
															 [V+][N+]

	 [Hub (Authenticator) node]
			 normal
			 response            <-- IDr, [CERT+],
															 AUTH(PSK),
															 [CP(CFG_REPLY)],
															 [N(RHP_AUTH_TICKET_SUPPORTED)]
															 [N+],
															 SA,
															 TSi,TSr,
															 [V+][N+]

      - If the authentication ticket service is disabled, N(RHP_AUTH_TICKET_SUPPORTED)
      	is just ignored by receiver.


  (1) INFORMATIONAL Exchange between a hub (Authenticator) node and a shortcut-initiator
      spoke node connecting a dynamic spoke-to-spoke (shortcut) tunnel.

   [Shortcut-initiator spoke node]
   request             --> N(RHP_AUTH_TICKET[TICKET_REQUEST and attributes])

                             - RHP_AUTH_TICKET: TICKET_REQUEST attributes:
                                 * Shortcut-responder Pub IP
                                 * Shortcut-responder Internal IP (For NHRP/DMVPN)
                                 * Shortcut-responder ID (if any)


	 [Hub (Authenticator) node]
   normal
   response            <-- N(RHP_AUTH_TICKET[TICKET_RESPONSE and attributes]),
                           N(RHP_ENC_AUTH_TICKET[TICKET_FORWARD and attributes])

                             - RHP_AUTH_TICKET: TICKET_RESPONSE attributes:
                                 * Shortcut-responder Pub IP
                                 * Shortcut-responder Internal IP (For NHRP/DMVPN)
                                 * Shortcut-responder ID (Only if the TICKET_REQUEST included the ID)
                                 * Ticket's expiration time
                                 * A new session key used as IKEv2 PSK between spokes.
                                   (i.e. It is used as a PSK to generate an AUTH payload
                                   and keying material).


                             - RHP_ENC_AUTH_TICKET: TICKET_FORWARD attributes:
                                 * Hub (Authenticator) ID
                                 * Shortcut-initiator ID
                                 * Shortcut-responder ID
                                 * Shortcut-initiator Pub IP
                                 * Shortcut-responder Pub IP
                                 * Shortcut-responder Internal IP (For NHRP/DMVPN)
                                 * Ticket's expiration time
                                 * A session key used as IKEv2 PSK between spokes.
                                   (i.e. It is used as a PSK to generate an AUTH payload
                                   and keying material).

      - If some error occurs, the hub node will respond a RHP_AUTH_TICKET Notify payload
        with AUTH_TKT_TYPE(TICKET_ERROR).


  (2) Exchanges between a shortcut-initiator spoke node and a shortcut-responder
      spoke node connecting a dynamic spoke-to-spoke (shortcut) tunnel.


		(2-1) IKE_SA_INIT Exchange

			[Shortcut-initiator] <--> [Shortcut-responder]


    (2-2) If the connectivity between the shortcut-peers is confirmed by IKE_SA_INIT
          exchange, the shortcut-initiator node starts (1) to get two authentication
          tickets (one is for the initiator and the other is for the shortcut-responder)
          including a session key and other attributes (See above) from the hub node.

          - The initiator gets a session key as a PSK to generate an AUTH payload
            and keying material from the N(RHP_AUTH_TICKET) received from the hub
            (Authenticator) node.

          - The ticket for the shortcut-responder is encyrpted by hub and forwarded
            to the shortcut-responder by shortcut-initiator in the following
            IKE_AUTH exchange (2.3).


		(2-3) IKE_AUTH Exchange

			[Shortcut-initiator]
			 request             --> IDi, [CERT+],
															 [N+],
															 [N(RHP_ENC_AUTH_TICKET)]
															 [IDr],
															 AUTH(PSK),
															 [CP(CFG_REQUEST)],
															 [N+],
															 SA, TSi, TSr,
															 [V+][N+]

			[Shortcut-responder]
			 normal
			 response            <-- IDr, [CERT+],
															 AUTH(PSK),
															 [CP(CFG_REPLY)],
															 [N+],
															 SA,
															 TSi,TSr,
															 [V+][N+]

			- The shortcut-responder spoke node gets a session key as a PSK to generate an
			  AUTH payload and keying material from the decrypted N(RHP_ENC_AUTH_TICKET)
			  received from the hub (Authenticator) node via the shortcut-initiator spoke
			  node.
			  Also, the shortcut-responder node checks the received attributes by
			  comparing them with the actual VPN connection's attributes (i.e. decrypted
			  IDs and IP addresses).

      - If the decrypted ticket's lifetime expired, the shortcut-responder node must
        reject the VPN connection from the shortcut-initiator node.

      - If some error occurs, the shortcut-responder node will respond a
        RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED Notify payload and clear
        the pending spole-to-spoke (shortcut) tunnel.

			- The shortcut-initiator spoke node MUST NOT reuse the RHP_ENC_AUTH_TICKET.

*/



void rhp_ikev2_auth_tkt_srch_clear_ctx(rhp_tkt_auth_srch_plds_ctx* s_pld_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_SRCH_CLEAR_CTX,"x",s_pld_ctx);
	return;
}


static void rhp_ikev2_auth_tkt_hb2spk_tx_tkt_req_bh(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* tx_ikemesg,rhp_packet* serialized_pkt)
{
	rhp_auth_tkt_pending_req* auth_tkt_req = vpn->auth_ticket.hb2spk_pend_req_q_head;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ_BH,"xxxxx",vpn,ikesa,tx_ikemesg,serialized_pkt,auth_tkt_req);

	while( auth_tkt_req ){

		RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ_BH_REQ,"xxxxxd",vpn,tx_ikemesg,serialized_pkt,auth_tkt_req,auth_tkt_req->hb2spk_tx_req_ikemesg,auth_tkt_req->hb2spk_is_tx_pending);

		if( auth_tkt_req->hb2spk_is_tx_pending &&
				auth_tkt_req->hb2spk_tx_req_ikemesg == tx_ikemesg ){

			auth_tkt_req->hb2spk_my_side = ikesa->side;
			memcpy(auth_tkt_req->hb2spk_my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

			auth_tkt_req->hb2spk_message_id = tx_ikemesg->get_mesg_id(tx_ikemesg);

			auth_tkt_req->hb2spk_is_tx_pending = 0;

			break;
		}

		auth_tkt_req = auth_tkt_req->next;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ_BH_RTRN,"xxxx",vpn,tx_ikemesg,serialized_pkt,auth_tkt_req);
	return;
}

void rhp_ikev2_auth_tkt_pending_req_free(rhp_auth_tkt_pending_req* auth_tkt_req)
{
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_PENDING_REQ_FREE,"xxxx",auth_tkt_req,auth_tkt_req->spk2spk_vpn_ref,RHP_VPN_REF(auth_tkt_req->spk2spk_vpn_ref),auth_tkt_req->hb2spk_tx_req_ikemesg);

	if( auth_tkt_req->spk2spk_vpn_ref ){
		rhp_vpn_unhold(auth_tkt_req->spk2spk_vpn_ref);
	}

	if( auth_tkt_req->hb2spk_tx_req_ikemesg ){
		rhp_ikev2_unhold_mesg(auth_tkt_req->hb2spk_tx_req_ikemesg);
	}

	_rhp_free(auth_tkt_req);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_PENDING_REQ_FREE_RTRN,"x",auth_tkt_req);
	return;
}

int rhp_ikev2_auth_tkt_hb2spk_tx_tkt_req(rhp_vpn_realm* tx_rlm,
		rhp_ip_addr* shortcut_resp_pub_addr,rhp_ip_addr* shortcut_resp_itnl_addr,
		rhp_ikev2_id* shortcut_resp_id,
		void (*rx_resp_cb)(rhp_vpn* rx_hb2spk_vpn,int my_ikesa_side,u8* my_ikesa_spi,
				int cb_err,rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* spk2spk_vpn),
				rhp_vpn* spk2spk_vpn)
{
	int err = -EINVAL;
  rhp_vpn_ref* tx_vpn_ref = NULL;
  rhp_vpn* tx_vpn = NULL;
  rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikev2_mesg* tx_ikemesg = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ,"xxxxYx",tx_rlm,shortcut_resp_pub_addr,shortcut_resp_itnl_addr,shortcut_resp_id,rx_resp_cb,spk2spk_vpn);
	rhp_ip_addr_dump("shortcut_resp_pub_addr",shortcut_resp_pub_addr);
	rhp_ip_addr_dump("shortcut_resp_itnl_addr",shortcut_resp_itnl_addr);


  RHP_LOCK(&(tx_rlm->lock));
  {

		if( !_rhp_atomic_read(&(tx_rlm->is_active)) ){

			RHP_UNLOCK(&(tx_rlm->lock));

			RHP_TRC_FREQ(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ_ACCESS_POINT_RLM_NOT_ACTIVE,"x",tx_rlm);
			goto error;
		}

		if( tx_rlm->access_point_peer_vpn_ref ){
			tx_vpn = RHP_VPN_REF(tx_rlm->access_point_peer_vpn_ref);
			tx_vpn_ref = rhp_vpn_hold_ref(tx_vpn);
		}
  }
  RHP_UNLOCK(&(tx_rlm->lock));

  if( tx_vpn == NULL ){
  	err = -ENOENT;
  	goto error;
  }


  err = rhp_ikev2_new_payload_n_auth_tkt_tx(
  				RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET,
  				RHP_PROTO_IKEV2_AUTH_TKT_TYPE_REQUEST,
  				&n_auth_tkt_payload);
  if( err ){
  	goto error;
  }


  if( shortcut_resp_id ){

  	u8* id_val = NULL;
  	int id_val_len = 0;
  	int id_type = 0;

  	rhp_ikev2_n_auth_tkt_attr* resp_id_attr;

  	resp_id_attr
  		= rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ID);
  	if( resp_id_attr == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,resp_id_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(resp_id_attr);
			goto error;
		}

  	err = rhp_ikev2_id_value(shortcut_resp_id,&id_val,&id_val_len,&id_type);
  	if( err ){
  		goto error;
  	}

  	resp_id_attr->set_attr_sub_type(resp_id_attr,id_type);

		err = resp_id_attr->set_attr_val(resp_id_attr,id_val_len,id_val);
		if( err ){
			_rhp_free(id_val);
			goto error;
		}

		_rhp_free(id_val);
  }


  if( shortcut_resp_pub_addr ){

  	rhp_ikev2_n_auth_tkt_attr* resp_pub_ip_attr;

  	resp_pub_ip_attr
  		= rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP);
  	if( resp_pub_ip_attr == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,resp_pub_ip_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(resp_pub_ip_attr);
			goto error;
		}

  	if( shortcut_resp_pub_addr->addr_family == AF_INET ){

  		resp_pub_ip_attr->set_attr_sub_type(resp_pub_ip_attr,4);

  		err = resp_pub_ip_attr->set_attr_val(resp_pub_ip_attr,4,shortcut_resp_pub_addr->addr.raw);
  		if( err ){
  			goto error;
  		}

  	}else if( shortcut_resp_pub_addr->addr_family == AF_INET6 ){

  		resp_pub_ip_attr->set_attr_sub_type(resp_pub_ip_attr,6);

  		err = resp_pub_ip_attr->set_attr_val(resp_pub_ip_attr,16,shortcut_resp_pub_addr->addr.raw);
  		if( err ){
  			goto error;
  		}

  	}else{
  		RHP_BUG("%d",shortcut_resp_pub_addr->addr_family);
  		err = -EINVAL;
  		goto error;
  	}
  }


  if( shortcut_resp_itnl_addr ){

  	rhp_ikev2_n_auth_tkt_attr* resp_itnl_ip_attr;

  	resp_itnl_ip_attr
  		= rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP);
  	if( resp_itnl_ip_attr == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}

  	err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,resp_itnl_ip_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(resp_itnl_ip_attr);
			goto error;
		}

  	if( shortcut_resp_itnl_addr->addr_family == AF_INET ){

  		resp_itnl_ip_attr->set_attr_sub_type(resp_itnl_ip_attr,4);

  		err = resp_itnl_ip_attr->set_attr_val(resp_itnl_ip_attr,4,shortcut_resp_itnl_addr->addr.raw);
  		if( err ){
  			goto error;
  		}

  	}else if( shortcut_resp_itnl_addr->addr_family == AF_INET6 ){

  		resp_itnl_ip_attr->set_attr_sub_type(resp_itnl_ip_attr,6);

  		err = resp_itnl_ip_attr->set_attr_val(resp_itnl_ip_attr,16,shortcut_resp_itnl_addr->addr.raw);
  		if( err ){
  			goto error;
  		}

  	}else{
  		RHP_BUG("%d",shortcut_resp_itnl_addr->addr_family);
  		err = -EINVAL;
  		goto error;
  	}
  }


  tx_ikemesg = rhp_ikev2_new_mesg_tx(RHP_PROTO_IKE_EXCHG_INFORMATIONAL,0,0);
  if( tx_ikemesg == NULL ){
    RHP_BUG("");
    goto error;
  }


  err = n_auth_tkt_payload->serialize(tx_ikemesg,n_auth_tkt_payload,NULL,NULL,&ikepayload);
  if( err ){
  	goto error;
  }

  tx_ikemesg->put_payload(tx_ikemesg,ikepayload);



  RHP_LOCK(&(tx_vpn->lock));

  if( !_rhp_atomic_read(&(tx_vpn->is_active)) ){

    RHP_UNLOCK(&(tx_vpn->lock));

  	err = -EINVAL;
  	goto error;
  }


  {
  	rhp_auth_tkt_pending_req* auth_tkt_req
  		= (rhp_auth_tkt_pending_req*)_rhp_malloc(sizeof(rhp_auth_tkt_pending_req));

  	if( auth_tkt_req == NULL ){

      RHP_UNLOCK(&(tx_vpn->lock));

  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}
  	memset(auth_tkt_req,0,sizeof(rhp_auth_tkt_pending_req));

  	auth_tkt_req->hb2spk_is_tx_pending = 1;
  	auth_tkt_req->spk2spk_vpn_ref = rhp_vpn_hold_ref(spk2spk_vpn);
  	auth_tkt_req->rx_resp_cb = rx_resp_cb;

  	auth_tkt_req->hb2spk_tx_req_ikemesg = tx_ikemesg;
    rhp_ikev2_hold_mesg(tx_ikemesg);

  	if( tx_vpn->auth_ticket.hb2spk_pend_req_q_head == NULL ){
  		tx_vpn->auth_ticket.hb2spk_pend_req_q_head = auth_tkt_req;
  	}else{
  		tx_vpn->auth_ticket.hb2spk_pend_req_q_tail->next = auth_tkt_req;
  	}
  	tx_vpn->auth_ticket.hb2spk_pend_req_q_tail = auth_tkt_req;
  }


  tx_ikemesg->packet_serialized = rhp_ikev2_auth_tkt_hb2spk_tx_tkt_req_bh;


  rhp_ikev2_send_request(tx_vpn,NULL,tx_ikemesg,RHP_IKEV2_MESG_HANDLER_AUTH_TKT_HUB2SPOKE);
  rhp_ikev2_unhold_mesg(tx_ikemesg);

  RHP_UNLOCK(&(tx_vpn->lock));
	rhp_vpn_unhold(tx_vpn_ref);

	rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ_RTRN,"xxxxxx",tx_rlm,spk2spk_vpn,tx_vpn_ref,tx_vpn,n_auth_tkt_payload,tx_ikemesg);
  return 0;


error:
	if( tx_vpn_ref ){
		rhp_vpn_unhold(tx_vpn_ref);
	}
	if( n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}
  if( tx_ikemesg ){
    rhp_ikev2_unhold_mesg(tx_ikemesg);
  }
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_TX_TKT_REQ_ERR,"xxxxxxE",tx_rlm,spk2spk_vpn,tx_vpn_ref,tx_vpn,n_auth_tkt_payload,tx_ikemesg,err);
	return err;
}


int rhp_ikev2_auth_tkt_srch_n_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,
		rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_tkt_auth_srch_plds_ctx* s_pld_ctx = (rhp_tkt_auth_srch_plds_ctx*)ctx;
	rhp_ikev2_n_payload* n_payload = (rhp_ikev2_n_payload*)payload->ext.n;
	u16 notify_mesg_type;

  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_SRCH_N_CB,"xdxx",rx_ikemesg,enum_end,payload,ctx);

	if( n_payload == NULL ){
		RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

	notify_mesg_type = n_payload->get_message_type(payload);

	if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET_SUPPORTED ){

		s_pld_ctx->peer_enabled = 1;
	  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_SRCH_N_CB_AUTH_TKT_HB2SPK_SUPPORTED,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_SUPPORTED_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET ){

		s_pld_ctx->n_auth_tkt_payload = payload;
	  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_SRCH_N_CB_AUTH_TKT_HB2SPK_AUTH_TKT,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_AUTH_TKT_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);

	}else if( notify_mesg_type == RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET ){

		s_pld_ctx->n_enc_auth_tkt_payload = payload;
	  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_SRCH_N_CB_AUTH_TKT_HB2SPK_ENC_AUTH_TKT,"x",rx_ikemesg);

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,s_pld_ctx->vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_ENC_AUTH_TKT_NOTIFY,"VP",s_pld_ctx->vpn,s_pld_ctx->ikesa);
	}

	err = 0;

error:
  RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB2SPK_SRCH_N_CB_RTRN,"xE",rx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_new_pkt_auth_tkt_hb2spk_error_notify(unsigned long rlm_id,
		rhp_ikev2_mesg* tx_ikemesg,u8 exchaneg_type,u32 message_id)
{
	int err = -EINVAL;
  rhp_ikev2_payload* ikepayload = NULL;
  rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_ERROR_NOTIFY,"uub",rlm_id,tx_ikemesg,message_id,exchaneg_type);

  if( exchaneg_type ){
	  tx_ikemesg->set_exchange_type(tx_ikemesg,exchaneg_type);
	  tx_ikemesg->set_mesg_id(tx_ikemesg,message_id);
  }

  {
  	err = rhp_ikev2_new_payload_n_auth_tkt_tx(
  					RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET,
  					RHP_PROTO_IKEV2_AUTH_TKT_TYPE_ERROR,
  					&n_auth_tkt_payload);

  	if( err ){
      RHP_BUG("");
  		goto error;
  	}

  	err = n_auth_tkt_payload->serialize(tx_ikemesg,
  					n_auth_tkt_payload,NULL,NULL,&ikepayload);
  	if( err ){
      RHP_BUG("");
  		goto error;
  	}
  }

  tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

 	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;


  rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_ERROR_NOTIFY_RTRN,"uux",rlm_id,message_id,tx_ikemesg);
  return 0;

error:
	if( n_auth_tkt_payload ){
	  rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}
  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_ERROR_NOTIFY_ERR,"uuE",rlm_id,message_id,err);
  return err;
}

static int _rhp_ikev2_new_pkt_auth_tkt_hb2spk_ike_auth_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_vpn_realm* rlm,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_REP,"xxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);

	{
	 	err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	 		RHP_BUG("");
	    goto error;
	 	}

	 	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET_SUPPORTED);
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_TX_SUPPORTED_NOTIFY,"VP",vpn,ikesa);

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_REP_RTRN,"xxxxx",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_REP_ERR,"xxxxxE",vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_auth_tkt_hb2Spk_ike_auth_req(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_tkt_auth_srch_plds_ctx s_pld_ctx;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_tkt_auth_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto error_l;
		}

		if( !rlm->nhrp.auth_tkt_enabled ){
			err = 0;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto ignored;
		}

		if( !rlm->is_access_point ){
			err = 0;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_NOT_ACCESS_POINT,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto ignored;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 auth_tkt_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET_SUPPORTED,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
				rhp_ikev2_mesg_srch_cond_n_mesg_ids,auth_tkt_n_ids,rhp_ikev2_auth_tkt_srch_n_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPKKE_AUTH_REQ_NTFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error;
		}
	}

	if( !s_pld_ctx.peer_enabled ){

		err = 0;

	  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_AUTH_PEER_DISABLED,"VP",vpn,ikesa);

		RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_PEER_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
		goto ignored;
	}


	{
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto error_l;
		}

		err = _rhp_ikev2_new_pkt_auth_tkt_hb2spk_ike_auth_rep(vpn,ikesa,rlm,rx_req_ikemesg,tx_resp_ikemesg);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_NEW_PKT_REP_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error_l;
		}

		RHP_UNLOCK(&(rlm->lock));
	}


	vpn->auth_ticket.conn_type = RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE;


  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_AUTH_ENABLED,"VPK",vpn,ikesa,rx_req_ikemesg);

ignored:
	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_RTRN,"xxxxb",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->auth_ticket.conn_type);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_AUTH_REQ_ERR,"VPE",vpn,ikesa,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_new_pkt_auth_tkt_hb2spk_ike_auth(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = NULL;
	rhp_ikev2_payload* ikepayload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			goto error_l;
		}

		if( !rlm->nhrp.auth_tkt_enabled ){
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
			RHP_UNLOCK(&(rlm->lock));
			goto ignored;
		}

		RHP_UNLOCK(&(rlm->lock));
  }

	{
	 	err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload);
	 	if( err ){
	     RHP_BUG("");
	     goto error;
	 	}

	 	tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);

	 	ikepayload->ext.n->set_protocol_id(ikepayload,0);

	 	ikepayload->ext.n->set_message_type(ikepayload,RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET_SUPPORTED);
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_TX_SUPPORTED_NOTIFY,"VP",vpn,ikesa);

ignored:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

error_l:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	}
error:
	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PKT_AUTH_TKT_HB2SPK_IKE_AUTH_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;
}


struct _rhp_ikev2_auth_tkt_hb_ctx {

	rhp_vpn_ref* vpn_ref;

	int my_ikesa_side;
	u8 my_ikesa_spi[RHP_PROTO_IKE_SPI_SIZE];

	rhp_ikev2_mesg* rx_ikemesg;
	rhp_ikev2_mesg* tx_ikemesg;

	rhp_ikev2_n_auth_tkt_payload* rx_n_auth_tkt_payload;
};
typedef struct _rhp_ikev2_auth_tkt_hb_ctx	rhp_ikev2_auth_tkt_hb_ctx;

static void _rhp_ikev2_auth_tkt_hb_ctx_free(rhp_ikev2_auth_tkt_hb_ctx* hb_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_BH_CTX_FREE,"xxxxx",hb_ctx,hb_ctx->vpn_ref,RHP_VPN_REF(hb_ctx->vpn_ref),hb_ctx->rx_ikemesg,hb_ctx->rx_n_auth_tkt_payload);

	if( hb_ctx->vpn_ref ){
		rhp_vpn_unhold(hb_ctx->vpn_ref);
	}

	if( hb_ctx->rx_ikemesg ){
		rhp_ikev2_unhold_mesg(hb_ctx->rx_ikemesg);
	}

	if( hb_ctx->rx_n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(hb_ctx->rx_n_auth_tkt_payload);
	}

	_rhp_free(hb_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_BH_CTX_FREE_RTRN,"x",hb_ctx);
	return;
}

static int _rhp_ikev2_auth_tkt_hb_issue_tkt_gen_enc_pld(rhp_vpn* resp_vpn,
		rhp_ikev2_id* init_id,
		rhp_ip_addr* init_pub_ip,
		rhp_ip_addr* resp_pub_ip,rhp_ip_addr* resp_itnl_ip,
		int shortcut_session_key_len,u8* shortcut_session_key,
		int64_t tkt_expire_time,
		rhp_ikev2_mesg* tx_ikemesg,
		rhp_ikev2_payload** n_payload_r)
{
	int err = -EINVAL;
	rhp_ikev2_n_auth_tkt_payload* n_enc_auth_tkt_payload = NULL;
	rhp_ikev2_n_auth_tkt_attr* aut_tkt_attr;
	u8* ike_id_val = NULL;
	int ike_id_val_len = 0;
	int ike_id_type = 0;
	rhp_ikev2_payload* n_payload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_GEN_ENC_PLD,"xxxxxpTxx",resp_vpn,init_id,init_pub_ip,resp_pub_ip,resp_itnl_ip,shortcut_session_key_len,shortcut_session_key,tkt_expire_time,tx_ikemesg,n_payload_r);
	rhp_ikev2_id_dump("init_id",init_id);
	rhp_ip_addr_dump("init_pub_ip",init_pub_ip);
	rhp_ip_addr_dump("resp_pub_ip",resp_pub_ip);
	rhp_ip_addr_dump("resp_itnl_ip",resp_itnl_ip);


	err = rhp_ikev2_new_payload_n_auth_tkt_tx(
					RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_ENC_AUTH_TICKET,
					RHP_PROTO_IKEV2_AUTH_TKT_TYPE_FORWARD,
					&n_enc_auth_tkt_payload);
	if( err ){
		goto error;
	}


	{
		err = rhp_ikev2_id_value(&(resp_vpn->my_id),&ike_id_val,&ike_id_val_len,&ike_id_type);
		if( err ){
			goto error;
		}

		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_AUTHENTICATOR_ID);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,(u16)ike_id_type);

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,ike_id_val_len,ike_id_val);
		if( err ){
			goto error;
		}

		_rhp_free(ike_id_val);
		ike_id_val = NULL;
		ike_id_val_len = 0;
		ike_id_type = 0;
	}

	{
		err = rhp_ikev2_id_value(init_id,&ike_id_val,&ike_id_val_len,&ike_id_type);
		if( err ){
			goto error;
		}

		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_ID);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,(u16)ike_id_type);

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,ike_id_val_len,ike_id_val);
		if( err ){
			goto error;
		}

		_rhp_free(ike_id_val);
		ike_id_val = NULL;
		ike_id_val_len = 0;
		ike_id_type = 0;
	}

	{
		err = rhp_ikev2_id_value(&(resp_vpn->peer_id),&ike_id_val,&ike_id_val_len,&ike_id_type);
		if( err ){
			goto error;
		}

		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ID);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,(u16)ike_id_type);

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,ike_id_val_len,ike_id_val);
		if( err ){
			goto error;
		}

		_rhp_free(ike_id_val);
		ike_id_val = NULL;
		ike_id_val_len = 0;
		ike_id_type = 0;
	}

	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_INITIATOR_PUB_IP);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		if( init_pub_ip->addr_family == AF_INET ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,4);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,4,init_pub_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else if( init_pub_ip->addr_family == AF_INET6 ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,6);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,16,init_pub_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else{

			RHP_BUG("%d",init_pub_ip->addr_family);
			err = -EINVAL;
			goto error;
		}
	}

	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		if( resp_pub_ip->addr_family == AF_INET ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,4);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,4,resp_pub_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else if( resp_pub_ip->addr_family == AF_INET6 ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,6);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,16,resp_pub_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else{

			RHP_BUG("%d",resp_pub_ip->addr_family);
			err = -EINVAL;
			goto error;
		}
	}

	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		if( resp_itnl_ip->addr_family == AF_INET ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,4);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,4,resp_itnl_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else if( resp_itnl_ip->addr_family == AF_INET6 ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,6);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,16,resp_itnl_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else{

			RHP_BUG("%d",resp_itnl_ip->addr_family);
			err = -EINVAL;
			goto error;
		}
	}

	{
		int64_t tkt_expire_time_n = (int64_t)_rhp_htonll(tkt_expire_time);

		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_EXPIRATION_TIME);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,sizeof(u64),(u8*)&tkt_expire_time_n);
		if( err ){
			goto error;
		}
	}


	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_SESSION_KEY);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_enc_auth_tkt_payload->add_attr(n_enc_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,shortcut_session_key_len,shortcut_session_key);
		if( err ){
			goto error;
		}
	}


	{
		rhp_ikesa* cur_ikesa = resp_vpn->ikesa_list_head;

		while( cur_ikesa ){

			if( cur_ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
					cur_ikesa->state == RHP_IKESA_STAT_REKEYING ){
				break;
			}

			cur_ikesa = cur_ikesa->next_vpn_list;
		}

		if( cur_ikesa == NULL ){
			err = -ENOENT;
			goto error;
		}


		err = n_enc_auth_tkt_payload->serialize(tx_ikemesg,n_enc_auth_tkt_payload,
	  				resp_vpn,cur_ikesa,&n_payload);
		if( err ){
			goto error;
		}
	}

	rhp_ikev2_payload_n_auth_tkt_free(n_enc_auth_tkt_payload);

	*n_payload_r = n_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_GEN_ENC_PLD_RTRN,"xxx",resp_vpn,tx_ikemesg,*n_payload_r);
	return 0;

error:
	if( n_enc_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_enc_auth_tkt_payload);
	}
	if( ike_id_val ){
		_rhp_free(ike_id_val);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_GEN_ENC_PLD_ERR,"xxE",resp_vpn,tx_ikemesg,err);
	return err;
}

static int _rhp_ikev2_auth_tkt_hb_issue_tkt_gen_pld(
		rhp_ip_addr* resp_pub_ip,rhp_ip_addr* resp_itnl_ip,
		int shortcut_session_key_len,u8* shortcut_session_key,
		int64_t tkt_expire_time,
		rhp_ikev2_mesg* tx_ikemesg,
		rhp_ikev2_payload** n_payload_r)
{
	int err = -EINVAL;
	rhp_ikev2_n_auth_tkt_payload* n_auth_tkt_payload = NULL;
	rhp_ikev2_n_auth_tkt_attr* aut_tkt_attr;
	rhp_ikev2_payload* n_payload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_GEN_PLD,"xxpTxx",resp_pub_ip,resp_itnl_ip,shortcut_session_key_len,shortcut_session_key,tkt_expire_time,tx_ikemesg,n_payload_r);
	rhp_ip_addr_dump("resp_pub_ip",resp_pub_ip);
	rhp_ip_addr_dump("resp_itnl_ip",resp_itnl_ip);


	err = rhp_ikev2_new_payload_n_auth_tkt_tx(
					RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET,
					RHP_PROTO_IKEV2_AUTH_TKT_TYPE_RESPONSE,
					&n_auth_tkt_payload);
	if( err ){
		goto error;
	}

	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		if( resp_pub_ip->addr_family == AF_INET ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,4);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,4,resp_pub_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else if( resp_pub_ip->addr_family == AF_INET6 ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,6);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,16,resp_pub_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else{

			RHP_BUG("%d",resp_pub_ip->addr_family);
			err = -EINVAL;
			goto error;
		}
	}

	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		if( resp_itnl_ip->addr_family == AF_INET ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,4);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,4,resp_itnl_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else if( resp_itnl_ip->addr_family == AF_INET6 ){

			aut_tkt_attr->set_attr_sub_type(aut_tkt_attr,6);

			err = aut_tkt_attr->set_attr_val(aut_tkt_attr,16,resp_itnl_ip->addr.raw);
			if( err ){
				goto error;
			}

		}else{

			RHP_BUG("%d",resp_itnl_ip->addr_family);
			err = -EINVAL;
			goto error;
		}
	}

	{
		int64_t tkt_expire_time_n = _rhp_htonll(tkt_expire_time);

		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_EXPIRATION_TIME);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,sizeof(int64_t),(u8*)&tkt_expire_time_n);
		if( err ){
			goto error;
		}
	}


	{
		aut_tkt_attr = rhp_ikev2_payload_n_auth_tkt_attr_alloc(RHP_PROTO_IKEV2_AUTH_TKT_ATTR_SESSION_KEY);
		if( aut_tkt_attr == NULL ){
			err = -ENOMEM;
			goto error;
		}

		err = n_auth_tkt_payload->add_attr(n_auth_tkt_payload,aut_tkt_attr);
		if( err ){
			rhp_ikev2_payload_n_auth_tkt_attr_free(aut_tkt_attr);
			goto error;
		}

		err = aut_tkt_attr->set_attr_val(aut_tkt_attr,shortcut_session_key_len,shortcut_session_key);
		if( err ){
			goto error;
		}
	}


	err = n_auth_tkt_payload->serialize(tx_ikemesg,n_auth_tkt_payload,
  				NULL,NULL,&n_payload);
	if( err ){
		goto error;
	}

	rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);

	*n_payload_r = n_payload;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_GEN_PLD_RTRN,"xx",tx_ikemesg,*n_payload_r);
	return 0;

error:
	if( n_auth_tkt_payload ){
		rhp_ikev2_payload_n_auth_tkt_free(n_auth_tkt_payload);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_GEN_PLD_ERR,"xE",tx_ikemesg,err);
	return err;
}

static void _rhp_ikev2_auth_tkt_hb_issue_tkt_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_ikev2_auth_tkt_hb_ctx* hb_ctx = (rhp_ikev2_auth_tkt_hb_ctx*)ctx;
	rhp_vpn* init_vpn = RHP_VPN_REF(hb_ctx->vpn_ref);
	rhp_ikev2_n_auth_tkt_attr *auth_tkt_resp_pub_ip, *auth_tkt_resp_itnl_ip;
	rhp_vpn_ref* resp_vpn_ref = NULL;
	rhp_vpn* resp_vpn = NULL;
	rhp_ip_addr init_pub_ip, resp_pub_ip, resp_itnl_ip;
	int shortcut_session_key_len = 0;
	u8* shortcut_session_key = NULL;
	int64_t tkt_expire_time;
	u8* attr_val;
	int attr_val_len;
	rhp_ikev2_payload *n_auth_tktpayload = NULL, *n_enc_auth_tktpayload = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_TASK,"dxx",worker_index,hb_ctx,init_vpn);

	memset(&init_pub_ip,0,sizeof(rhp_ip_addr));
	memset(&resp_itnl_ip,0,sizeof(rhp_ip_addr));
	memset(&resp_itnl_ip,0,sizeof(rhp_ip_addr));


	{
		auth_tkt_resp_pub_ip
			= hb_ctx->rx_n_auth_tkt_payload->get_attr(hb_ctx->rx_n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP,4);

		if( auth_tkt_resp_pub_ip == NULL ){

			auth_tkt_resp_pub_ip
				= hb_ctx->rx_n_auth_tkt_payload->get_attr(hb_ctx->rx_n_auth_tkt_payload,
						RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_PUB_IP,6);

			if( auth_tkt_resp_pub_ip == NULL ){
				err = -ENOENT;
				goto error_notify;
			}

			resp_pub_ip.addr_family = AF_INET6;

			attr_val = auth_tkt_resp_pub_ip->get_attr_val(auth_tkt_resp_pub_ip,&attr_val_len);
			if( attr_val == NULL || attr_val_len != 16 ){
				err = -EINVAL;
				goto error_notify;
			}
			memcpy(resp_pub_ip.addr.raw,attr_val,attr_val_len);

		}else{

			resp_pub_ip.addr_family = AF_INET;

			attr_val = auth_tkt_resp_pub_ip->get_attr_val(auth_tkt_resp_pub_ip,&attr_val_len);
			if( attr_val == NULL || attr_val_len != 4 ){
				err = -EINVAL;
				goto error_notify;
			}
			memcpy(resp_pub_ip.addr.raw,attr_val,attr_val_len);
		}
	}

	{
		auth_tkt_resp_itnl_ip
			= hb_ctx->rx_n_auth_tkt_payload->get_attr(hb_ctx->rx_n_auth_tkt_payload,
					RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP,4);

		if( auth_tkt_resp_itnl_ip == NULL ){

			auth_tkt_resp_itnl_ip
				= hb_ctx->rx_n_auth_tkt_payload->get_attr(hb_ctx->rx_n_auth_tkt_payload,
						RHP_PROTO_IKEV2_AUTH_TKT_ATTR_RESPONDER_ITNL_IP,6);

			if( auth_tkt_resp_itnl_ip == NULL ){
				err = -ENOENT;
				goto error_notify;
			}

			resp_itnl_ip.addr_family = AF_INET6;

			attr_val = auth_tkt_resp_itnl_ip->get_attr_val(auth_tkt_resp_itnl_ip,&attr_val_len);
			if( attr_val == NULL || attr_val_len != 16 ){
				err = -EINVAL;
				goto error_notify;
			}
			memcpy(resp_itnl_ip.addr.raw,attr_val,attr_val_len);

		}else{

			resp_itnl_ip.addr_family = AF_INET;

			attr_val = auth_tkt_resp_itnl_ip->get_attr_val(auth_tkt_resp_itnl_ip,&attr_val_len);
			if( attr_val == NULL || attr_val_len != 4 ){
				err = -EINVAL;
				goto error_notify;
			}
			memcpy(resp_itnl_ip.addr.raw,attr_val,attr_val_len);
		}
	}


	err = hb_ctx->rx_ikemesg->rx_get_src_addr(hb_ctx->rx_ikemesg,&init_pub_ip);
	if( err ){
		goto error_notify;
	}


	resp_vpn_ref = rhp_vpn_get_by_nhrp_peer_nbma_proto_addrs(
									init_vpn->vpn_realm_id,&resp_pub_ip,&resp_itnl_ip);
	resp_vpn = RHP_VPN_REF(resp_vpn_ref);
	if( resp_vpn == NULL ){
		err = -ENOENT;
		goto error_notify;
	}


	tkt_expire_time
		= (int64_t)(_rhp_get_realtime() + (time_t)rhp_gcfg_ikev2_auth_tkt_lifetime);


	{
		shortcut_session_key = (u8*)_rhp_malloc(rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_len);
		if( shortcut_session_key == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error_notify;
		}
		shortcut_session_key_len = rhp_gcfg_ikev2_auth_tkt_shortcut_session_key_len;

		err = rhp_random_bytes(shortcut_session_key,shortcut_session_key_len);
		if( err ){
			RHP_BUG("%d",err);
			goto error_notify;
		}
	}



	RHP_LOCK(&(resp_vpn->lock));

	if( !_rhp_atomic_read(&(resp_vpn->is_active)) ){

		RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_TASK_HB2SPK_VPN_NOT_ACTIVE,"dxxxxd",worker_index,hb_ctx,init_vpn,resp_vpn_ref,resp_vpn,resp_vpn->auth_ticket.conn_type);

		RHP_UNLOCK(&(resp_vpn->lock));

		err = -ENOENT;
		goto error_notify;
	}

	if( resp_vpn->auth_ticket.conn_type != RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE ){

		RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_TASK_NOT_HB2SPK_VPN,"dxxxxd",worker_index,hb_ctx,init_vpn,resp_vpn_ref,resp_vpn,resp_vpn->auth_ticket.conn_type);

		RHP_UNLOCK(&(resp_vpn->lock));

		err = -ENOENT;
		goto error_notify;
	}


	err = _rhp_ikev2_auth_tkt_hb_issue_tkt_gen_pld(
					&resp_pub_ip,&resp_itnl_ip,
					shortcut_session_key_len,shortcut_session_key,
					tkt_expire_time,hb_ctx->tx_ikemesg,
					&n_auth_tktpayload);
	if( err ){

		RHP_UNLOCK(&(resp_vpn->lock));

		goto error_notify;
	}


	err = _rhp_ikev2_auth_tkt_hb_issue_tkt_gen_enc_pld(resp_vpn,
					&(init_vpn->peer_id), // Immutable value
					&init_pub_ip,
					&resp_pub_ip,&resp_itnl_ip,
					shortcut_session_key_len,shortcut_session_key,
					tkt_expire_time,hb_ctx->tx_ikemesg,
					&n_enc_auth_tktpayload);
	if( err ){

		RHP_UNLOCK(&(resp_vpn->lock));

		goto error_notify;
	}

	RHP_UNLOCK(&(resp_vpn->lock));



	RHP_LOCK(&(init_vpn->lock));

	if( !_rhp_atomic_read(&(init_vpn->is_active)) ){

		RHP_UNLOCK(&(init_vpn->lock));

		err = -ENOENT;
		goto error_notify;
	}


	hb_ctx->tx_ikemesg->put_payload(hb_ctx->tx_ikemesg,n_auth_tktpayload);
	n_auth_tktpayload = NULL;

	hb_ctx->tx_ikemesg->put_payload(hb_ctx->tx_ikemesg,n_enc_auth_tktpayload);
	n_enc_auth_tktpayload = NULL;


  rhp_ikev2_call_next_rx_request_mesg_handlers(hb_ctx->rx_ikemesg,init_vpn,
  		hb_ctx->my_ikesa_side,hb_ctx->my_ikesa_spi,
  		hb_ctx->tx_ikemesg,RHP_IKEV2_MESG_HANDLER_AUTH_TKT_HUB2SPOKE);


	RHP_UNLOCK(&(init_vpn->lock));


	_rhp_free_zero(shortcut_session_key,shortcut_session_key_len);

	_rhp_ikev2_auth_tkt_hb_ctx_free(hb_ctx);

	rhp_vpn_unhold(resp_vpn_ref);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_TASK_RTRN,"dxxxxT",worker_index,hb_ctx,init_vpn,resp_vpn_ref,resp_vpn,tkt_expire_time);
	return;


error_notify:

	if( init_vpn ){

		RHP_LOCK(&(init_vpn->lock));

		if( _rhp_atomic_read(&(init_vpn->is_active)) ){

			rhp_ikesa* cur_ikesa = init_vpn->ikesa_get(init_vpn,hb_ctx->my_ikesa_side,hb_ctx->my_ikesa_spi);
			if( cur_ikesa ){

				err = _rhp_ikev2_new_pkt_auth_tkt_hb2spk_error_notify(init_vpn->vpn_realm_id,
								hb_ctx->tx_ikemesg,0,0);
				if( !err ){

					rhp_ikev2_call_next_rx_request_mesg_handlers(hb_ctx->rx_ikemesg,init_vpn,
							hb_ctx->my_ikesa_side,hb_ctx->my_ikesa_spi,
							hb_ctx->tx_ikemesg,RHP_IKEV2_MESG_HANDLER_AUTH_TKT_HUB2SPOKE);
				}

				RHP_LOG_DE(RHP_LOG_SRC_IKEV2,init_vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_TX_ERR_NOTIFY,"VP",init_vpn,cur_ikesa);
			}
		}

		RHP_UNLOCK(&(init_vpn->lock));
	}

	if( resp_vpn ){
		rhp_vpn_unhold(resp_vpn_ref);
	}

	if( n_auth_tktpayload ){
		rhp_ikev2_destroy_payload(n_auth_tktpayload);
	}

	if( n_enc_auth_tktpayload ){
		rhp_ikev2_destroy_payload(n_enc_auth_tktpayload);
	}

	if( shortcut_session_key ){
		_rhp_free_zero(shortcut_session_key,shortcut_session_key_len);
	}

	_rhp_ikev2_auth_tkt_hb_ctx_free(hb_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_TASK_ERR,"dxxxE",worker_index,hb_ctx,init_vpn,resp_vpn);
	return;
}

static int _rhp_ikev2_auth_tkt_hb_issue_tkt(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg,
		rhp_ikev2_n_auth_tkt_payload* rx_n_auth_tkt_payload)
{
	int err = -EINVAL;
	rhp_ikev2_auth_tkt_hb_ctx* hb_ctx = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT,"xxxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,rx_n_auth_tkt_payload);


	hb_ctx = (rhp_ikev2_auth_tkt_hb_ctx*)_rhp_malloc(sizeof(rhp_ikev2_auth_tkt_hb_ctx));
	if( hb_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(hb_ctx,0,sizeof(rhp_ikev2_auth_tkt_hb_ctx));


	hb_ctx->vpn_ref = rhp_vpn_hold_ref(vpn);

	hb_ctx->my_ikesa_side = ikesa->side;
	memcpy(hb_ctx->my_ikesa_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE);

	hb_ctx->rx_ikemesg = rx_req_ikemesg;
	rhp_ikev2_hold_mesg(rx_req_ikemesg);

	hb_ctx->tx_ikemesg = tx_resp_ikemesg;
	rhp_ikev2_hold_mesg(tx_resp_ikemesg);

	hb_ctx->rx_n_auth_tkt_payload = rx_n_auth_tkt_payload;


	err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,
					_rhp_ikev2_auth_tkt_hb_issue_tkt_task,hb_ctx);

	if( err ){

		RHP_BUG("%d",err);

		hb_ctx->rx_n_auth_tkt_payload = NULL;
		_rhp_ikev2_auth_tkt_hb_ctx_free(hb_ctx);

		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_RTRN,"xxxxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,rx_n_auth_tkt_payload,hb_ctx);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_ISSUE_TKT_ERR,"xxxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,rx_n_auth_tkt_payload,err);
	return err;
}


static int _rhp_ikev2_rx_auth_tkt_hb2spk_ike_auth_rep(rhp_vpn* vpn,
		rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_tkt_auth_srch_plds_ctx s_pld_ctx;
	rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_tkt_auth_srch_plds_ctx));

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
  		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){
    RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }

  rlm = vpn->rlm;
  if( rlm == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  {
		RHP_LOCK(&(rlm->lock));

		if( !_rhp_atomic_read(&(rlm->is_active)) ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_RLM_NOT_ACTIVE,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
			goto error_l;
		}

		if( !rlm->nhrp.auth_tkt_enabled ){
			err = 0;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
			goto ignored;
		}

		if( rlm->is_access_point ){
			err = 0;
			RHP_UNLOCK(&(rlm->lock));
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_IS_ACCESS_POINT,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
			goto ignored;
		}

		RHP_UNLOCK(&(rlm->lock));
  }


  if( vpn->cfg_peer == NULL || !vpn->cfg_peer->is_access_point ){
		err = 0;
		RHP_UNLOCK(&(rlm->lock));
		RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_PEER_IS_NOT_ACCESS_POINT,"xxxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->cfg_peer);
		goto ignored;
	}



	s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 auth_tkt_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET_SUPPORTED,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,auth_tkt_n_ids,
						rhp_ikev2_auth_tkt_srch_n_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){

		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPKKE_AUTH_NTFY_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
			goto error;
		}
		err = 0;
	}

	if( !s_pld_ctx.peer_enabled ){
		err = 0;
    RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_PEER_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		goto ignored;
	}


	vpn->auth_ticket.conn_type = RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE;


ignored:
	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_RTRN,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
	return 0;

error_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_AUTH_REP_ERR,"VPE",vpn,ikesa,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REP_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_auth_tkt_hb2Spk_info_req(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_req_ikemesg,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_tkt_auth_srch_plds_ctx s_pld_ctx;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REQ,"xxxxb",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,vpn->auth_ticket.conn_type);

	memset(&s_pld_ctx,0,sizeof(rhp_tkt_auth_srch_plds_ctx));

  if( rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
   		rx_req_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){

  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( vpn->auth_ticket.conn_type != RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE ){

  	err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REQ_DISALBED,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  	goto ignore;
  }



  s_pld_ctx.vpn = vpn;
	s_pld_ctx.ikesa = ikesa;

	{
		s_pld_ctx.dup_flag = 0;
		u16 auth_tkt_n_ids[2] = { RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_AUTH_TICKET,
														RHP_PROTO_IKE_NOTIFY_RESERVED};

		err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
						rhp_ikev2_mesg_srch_cond_n_mesg_ids,auth_tkt_n_ids,
						rhp_ikev2_auth_tkt_srch_n_cb,&s_pld_ctx);

		if( err && err != RHP_STATUS_ENUM_OK && err != -ENOENT ){
			RHP_TRC(0,RHPTRCID_RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REQ_NTFY_PLD_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
			goto error;
		}

		err = 0;
	}

	if( s_pld_ctx.n_auth_tkt_payload ){

		rhp_ikev2_n_auth_tkt_payload* rx_n_auth_tkt_payload = NULL;

		err = rhp_ikev2_new_payload_n_auth_tkt_rx(rx_req_ikemesg,s_pld_ctx.n_auth_tkt_payload,
				&rx_n_auth_tkt_payload);
		if( err ){
			goto error_notify;
		}


		if( rx_n_auth_tkt_payload->get_auth_tkt_type(rx_n_auth_tkt_payload)
					!= RHP_PROTO_IKEV2_AUTH_TKT_TYPE_REQUEST ){

			rhp_ikev2_payload_n_auth_tkt_free(rx_n_auth_tkt_payload);

			goto error_notify;
		}


		err = _rhp_ikev2_auth_tkt_hb_issue_tkt(vpn,ikesa,
						rx_req_ikemesg,tx_resp_ikemesg,rx_n_auth_tkt_payload);
		if( err ){

			rhp_ikev2_payload_n_auth_tkt_free(rx_n_auth_tkt_payload);

			goto error_notify;
		}

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_INFO_REQ,"VPK",vpn,ikesa,rx_req_ikemesg);

		err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

	}else{

		err = 0;
	}

ignore:
	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);


  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REQ_RTRN,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return err;


error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_INFO_REQ_ERR,"VPKE",vpn,ikesa,rx_req_ikemesg,err);

	rhp_ikev2_auth_tkt_srch_clear_ctx(&s_pld_ctx);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REQ_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	return 0; // Error is ignored.


error_notify:
	err = _rhp_ikev2_new_pkt_auth_tkt_hb2spk_error_notify(vpn->vpn_realm_id,tx_resp_ikemesg,0,0);
	if( err ){
		RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REQ_TX_ERR_NOTIFY_ERR,"xxxxE",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err);
	}
  RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_TX_ERR_NOTIFY,"VP",vpn,ikesa);

	// err == 0 is OK.

	goto error;
}

static int _rhp_ikev2_auth_tkt_clear_dead_req(rhp_vpn* vpn)
{
	rhp_auth_tkt_pending_req *auth_tkt_req = vpn->auth_ticket.hb2spk_pend_req_q_head, *auth_tkt_req_p = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_CLEAR_DEAD_REQ,"xx",vpn,auth_tkt_req);

	while( auth_tkt_req ){

		rhp_auth_tkt_pending_req* auth_tkt_req_n = auth_tkt_req->next;
		rhp_ikesa* cur_ikesa = vpn->ikesa_list_head;

		while( cur_ikesa ){

			if( (cur_ikesa->state == RHP_IKESA_STAT_ESTABLISHED ||
					 cur_ikesa->state == RHP_IKESA_STAT_REKEYING) &&
					auth_tkt_req->hb2spk_my_side == cur_ikesa->side &&
					!memcmp(auth_tkt_req->hb2spk_my_spi,cur_ikesa->get_my_spi(cur_ikesa),RHP_PROTO_IKE_SPI_SIZE) ){

				RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_CLEAR_DEAD_REQ_IKESA,"xxxLdddp",vpn,auth_tkt_req,cur_ikesa,"IKESA_STAT",cur_ikesa->state,auth_tkt_req->hb2spk_my_side,cur_ikesa->side,RHP_PROTO_IKE_SPI_SIZE,auth_tkt_req->hb2spk_my_spi);

				break;
			}

			cur_ikesa = cur_ikesa->next_vpn_list;
		}

		if( !auth_tkt_req->hb2spk_is_tx_pending && cur_ikesa == NULL ){

			if( auth_tkt_req_p ){
				auth_tkt_req_p->next = auth_tkt_req->next;
			}else{
				vpn->auth_ticket.hb2spk_pend_req_q_head = auth_tkt_req->next;
			}

			auth_tkt_req->next = NULL;

			auth_tkt_req->rx_resp_cb(vpn,auth_tkt_req->hb2spk_my_side,auth_tkt_req->hb2spk_my_spi,
					-EINVAL,NULL,RHP_VPN_REF(auth_tkt_req->spk2spk_vpn_ref));

			rhp_ikev2_auth_tkt_pending_req_free(auth_tkt_req);

		}else{

			auth_tkt_req_p = auth_tkt_req;
		}

		auth_tkt_req = auth_tkt_req_n;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_AUTH_TKT_HB_CLEAR_DEAD_REQ_RTRN,"x",vpn);
	return 0;
}

static int _rhp_ikev2_rx_auth_tkt_hb2spk_info_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	int handle_resp = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REP,"xxxxb",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,vpn->auth_ticket.conn_type);

  if( rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV4_IKE &&
   		rx_resp_ikemesg->rx_pkt->type != RHP_PKT_IPV6_IKE ){

  	RHP_BUG("");
    err = RHP_STATUS_INVALID_MSG;
    goto error;
  }


  if( vpn->auth_ticket.conn_type != RHP_AUTH_TKT_CONN_TYPE_HUB2SPOKE ){

  	err = 0;
		RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REP_DISALBED,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
  	goto ignore;
  }


  _rhp_ikev2_auth_tkt_clear_dead_req(vpn);


  {
  	rhp_auth_tkt_pending_req *auth_tkt_req = vpn->auth_ticket.hb2spk_pend_req_q_head, *auth_tkt_req_p = NULL;
  	while( auth_tkt_req ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REP_AUTH_TKT_REQ,"xxxxduuddpp",vpn,ikesa,rx_resp_ikemesg,auth_tkt_req,auth_tkt_req->hb2spk_is_tx_pending,auth_tkt_req->hb2spk_message_id,rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg),auth_tkt_req->hb2spk_my_side,ikesa->side,RHP_PROTO_IKE_SPI_SIZE,auth_tkt_req->hb2spk_my_spi,RHP_PROTO_IKE_SPI_SIZE,ikesa->get_my_spi(ikesa));

  		if( !auth_tkt_req->hb2spk_is_tx_pending &&
  				auth_tkt_req->hb2spk_message_id == rx_resp_ikemesg->get_mesg_id(rx_resp_ikemesg) &&
  				auth_tkt_req->hb2spk_my_side == ikesa->side &&
  				!memcmp(auth_tkt_req->hb2spk_my_spi,ikesa->get_my_spi(ikesa),RHP_PROTO_IKE_SPI_SIZE) ){

  			if( auth_tkt_req_p ){
  				auth_tkt_req_p->next = auth_tkt_req->next;
  			}else{
  				vpn->auth_ticket.hb2spk_pend_req_q_head = auth_tkt_req->next;
  			}

  			auth_tkt_req->next = NULL;

  			auth_tkt_req->rx_resp_cb(vpn,auth_tkt_req->hb2spk_my_side,auth_tkt_req->hb2spk_my_spi,
  					0,rx_resp_ikemesg,RHP_VPN_REF(auth_tkt_req->spk2spk_vpn_ref));

  			rhp_ikev2_auth_tkt_pending_req_free(auth_tkt_req);

  			handle_resp = 1;

  			break;
  		}

  		auth_tkt_req_p = auth_tkt_req;
  		auth_tkt_req = auth_tkt_req->next;
  	}
  }


  if( handle_resp ){

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_INFO_REP,"VPK",vpn,ikesa,rx_resp_ikemesg);

		err = RHP_STATUS_IKEV2_MESG_HANDLER_PENDING;

	}else{

		err = 0;
	}

ignore:

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REP_RTRN,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;


error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_INFO_REP_ERR,"VPKE",vpn,ikesa,rx_resp_ikemesg,err);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_INFO_REP_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return 0; // Error is ignored.
}


int rhp_ikev2_rx_auth_tkt_hb2spk_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REQ,"xxLdGxLb",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		err = 0;
  	goto error;

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( !RHP_PROTO_IKE_HDR_INITIATOR(rx_req_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REQ_INVALID_MESG1,"xx",rx_req_ikemesg,vpn);
			goto error;
	  }
	}

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REQ_NOT_DECRYPTED,"xx",rx_req_ikemesg,vpn);
  	goto error;
  }

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REQ_NO_IKESA,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REQ_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
		goto error;
	}

  if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

  	err = _rhp_ikev2_rx_auth_tkt_hb2Spk_ike_auth_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
  	if( err ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_IKE_AUTH_REQ_CALL_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  		goto error;
  	}

  }else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

  	if( vpn->nhrp.role == RHP_NHRP_SERVICE_SERVER ){

  		err = _rhp_ikev2_rx_auth_tkt_hb2Spk_info_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
    	if( err ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2PSK_INFO_REQ_CALL_ERR,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
    		goto error;
    	}
  	}
  }

  err = 0;

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_REQ_ERR,"VPKE",vpn,ikesa,rx_req_ikemesg,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}


int rhp_ikev2_rx_auth_tkt_hb2spk_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP,"xxLdGxLb",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type);

	if( my_ikesa_spi == NULL ){
    RHP_BUG("");
    err = -EINVAL;
    goto error;
  }

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_NO_IKESA,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( exchange_type != RHP_PROTO_IKE_EXCHG_IKE_SA_INIT &&
			exchange_type != RHP_PROTO_IKE_EXCHG_SESS_RESUME){

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		if( ikesa->state != RHP_IKESA_STAT_ESTABLISHED && ikesa->state != RHP_IKESA_STAT_REKEYING ){
			err = 0;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_IKESA_STATE_NOT_INTERESTED,"xxLdGLd",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKESA_STAT",ikesa->state);
			goto error;
		}
	}


	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_INVALID_MESG_IKE_SA_INIT_NOT_RESPONDER,"xx",rx_resp_ikemesg,vpn);
			goto error;
	  }

		err = _rhp_ikev2_new_pkt_auth_tkt_hb2spk_ike_auth(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		if( err ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_IKE_SA_INIT_NEW_PKT_ERR,"xxE",rx_resp_ikemesg,vpn,err);
			goto error;
		}

	}else if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH ){

		if( RHP_PROTO_IKE_HDR_INITIATOR(rx_resp_ikemesg->rx_pkt->app.ikeh->flag) ){
			err = RHP_STATUS_INVALID_MSG;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_INVALID_MESG_IKE_AUTH_NOT_RESPONDER,"xx",rx_resp_ikemesg,vpn);
			goto error;
	  }

		err = _rhp_ikev2_rx_auth_tkt_hb2spk_ike_auth_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
		if( err ){
    	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_Hb2SPK_IKE_AUTH_REP_CALL_ERR,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  		goto error;
		}

  }else if( exchange_type == RHP_PROTO_IKE_EXCHG_INFORMATIONAL ){

  	if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT ){

  		err = _rhp_ikev2_rx_auth_tkt_hb2spk_info_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
    	if( err ){
      	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_Hb2SPK_INFO_REP_CALL_ERR,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
    		goto error;
    	}
  	}
  }

  err = 0;

error:
	if( err ){
		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_IKE_AUTH_TKT_HUB2SPOKE_RX_REP_ERR,"VPKE",vpn,ikesa,rx_resp_ikemesg,err);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_AUTH_TKT_HB2SPK_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}
