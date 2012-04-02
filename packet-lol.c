/* packet-Plol.c
 * Routines for League of Legends GC dissection
 * Copyright 2011, Intline9 <intline9@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "lol.h"

/* Special CRC */
static guint16 crcsum(guint16 crc, const guint8* message, guint length);

static gboolean haveCrc = FALSE;
gboolean initialized = FALSE;

byte key[16];
gboolean isKey = FALSE;

/* Handlers */
static gint ett_lol = -1;
static gint ett_enet = -1;
static int proto_lol = -1;
static int proto_enet = -1;
static dissector_handle_t lol_handle;

/* Structure */
/* Enet */
static int hf_enet_header = -1;
static int hf_enet_peerId = -1;
static int hf_enet_sessionId = -1;
static int hf_enet_sentTime = -1;
static int hf_enet_flags = -1;
static int hf_enet_checksum = -1;

static const value_string commands[] = {
	{ 0, "ENET_PROTOCOL_COMMAND_NONE" },
	{ 1, "ENET_PROTOCOL_COMMAND_ACKNOWLEDGE" },
	{ 2, "ENET_PROTOCOL_COMMAND_CONNECT" },
	{ 3, "ENET_PROTOCOL_COMMAND_VERIFY_CONNECT" },
	{ 4, "ENET_PROTOCOL_COMMAND_DISCONNECT" },
	{ 5, "ENET_PROTOCOL_COMMAND_PING" },
	{ 6, "ENET_PROTOCOL_COMMAND_SEND_RELIABLE" },
	{ 7, "ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE" },
	{ 8, "ENET_PROTOCOL_COMMAND_SEND_FRAGMENT" },
	{ 9, "ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED" },
	{ 10, "ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT" },
	{ 11, "ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE" },
	{ 12, "ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT" },
};
static int hf_enet_commandHeader = -1;
static int hf_enet_command = -1;
static int hf_enet_channelId = -1;
static int hf_enet_sequenceNumber = -1;

static int hf_lol_command = -1;
static int hf_lol_length = -1;
static int hf_lol_packet = -1;

/* Global sample preference ("controls" display of numbers) */
guint8 *gPREF_KEY = NULL;
guint gPREF_PORT = 5000;

#define LOL_ACK_FLAG 0x01
void proto_register_lol(void)
{
	module_t *lol_module;
	
	static hf_register_info hf_enet[] = {
		{ &hf_enet_header,
			{"Enet Header", "enet.header",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL}
		},

		{ &hf_enet_peerId,
			{"Peer ID", "enet.header.peerid",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_enet_sessionId,
			{"Session ID", "enet.header.sessionid",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_enet_flags,
		{"Flags", "enet.header.flags",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_enet_sentTime,
			{"Send Time", "enet.header.senttime",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_enet_checksum,
		{"Checksum", "enet.header.checksum",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		/* Command header */
		{ &hf_enet_commandHeader,
			{"Enet Command", "enet.cheader",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_enet_command,
			{"Command", "enet.cheader.command",
			FT_UINT8, BASE_DEC,
			VALS(commands), 0x0F,
			NULL, HFILL}
		},
		{ &hf_enet_channelId,
			{"Channel ID", "enet.cheader.channelid",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_enet_sequenceNumber,
		{"Sequence number", "enet.cheader.seqno",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},

		/* Send structs */
		{ &hf_lol_command,
			{"Command", "lol.command",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_lol_length,
			{"Data length", "lol.length",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_lol_packet,
			{"Data", "lol.data",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_enet,
		&ett_lol
	};

	proto_enet = proto_register_protocol(
		"Enet",								/* name */
		"Enet",								/* short name */
		"enet"								/* abbrev */
	);

	proto_lol = proto_register_protocol(
		"League of Legends",				/* name */
		"LoL",								/* short name */
		"lol"								/* abbrev */
	);
	
	proto_register_field_array(proto_enet, hf_enet, array_length(hf_enet));
	proto_register_subtree_array(ett, array_length(ett));
	
	/* Preferences */
	lol_module = prefs_register_protocol(proto_lol, proto_reg_handoff_lol);
	

	gPREF_KEY = (guint8*)g_malloc(32 * sizeof(guint8)); memset(gPREF_KEY, 0, 32 * sizeof(guint8));
	prefs_register_string_preference(lol_module,
		"lolpref.key",
	    "Blowfish key",
		"The key needed for this game session to decrypt the packets.",
		&gPREF_KEY
	);
	
	prefs_register_uint_preference(lol_module,
		"lolpref.port",
		"LoL GC port",
		"Port to listen on for this game session.",
		10,
		&gPREF_PORT
	);
	
	/* Start the watchdog thread */
	start_listener();
	atexit(stop_listener);
}

void set_single_port(guint port)
{
	int i;
	for(i = LOL_PORT_MIN; i < LOL_PORT_MAX; i++)
		dissector_delete_uint("udp.port", i, lol_handle);
	dissector_add_uint("udp.port", port, lol_handle);
}

void proto_reg_handoff_lol(void)
{
	int i;
	static int currentPort;
	
	if(!initialized)
	{
		lol_handle = create_dissector_handle(dissect_lol, proto_lol);
		initialized = TRUE;
	}
	
	for(i = LOL_PORT_MIN; i < LOL_PORT_MAX; i++)
		dissector_add_uint("udp.port", i, lol_handle);
}

//  GSList      *pfd;         /**< Per frame proto data */
//  guint32      num;         /**< Frame number */
//  guint32      pkt_len;     /**< Packet length */
//  guint32      cap_len;     /**< Amount actually captured */
//  guint32      cum_bytes;   /**< Cumulative bytes into the capture */
//  gint64       file_off;    /**< File offset */
//  guint16      subnum;      /**< subframe number, for protocols that require this */
//  gint16       lnk_t;       /**< Per-packet encapsulation/data-link type */
//  struct {
    //unsigned int passed_dfilter : 1; /**< 1 = display, 0 = no display */
    //unsigned int encoding       : 2; /**< Character encoding (ASCII, EBCDIC...) */
    //unsigned int visited        : 1; /**< Has this packet been visited yet? 1=Yes,0=No*/
    //unsigned int marked         : 1; /**< 1 = marked by user, 0 = normal */
    //unsigned int ref_time       : 1; /**< 1 = marked as a reference time frame, 0 = normal */
    //unsigned int ignored        : 1; /**< 1 = ignore this frame, 0 = normal */
  //} flags;
static guint dissect_enet_commandHeader(tvbuff_t *tvb, packet_info *pinfo, proto_tree *enetTree, ENetProtocol *command, guint offset)
{
	proto_item *enetCommandHeader = NULL, *item = NULL;

	item = proto_tree_add_item(enetTree, hf_enet_commandHeader, tvb, offset, 4, FALSE);
	enetCommandHeader = proto_item_add_subtree(item, ett_enet);

	proto_tree_add_item(enetCommandHeader, hf_enet_command, tvb, offset, 1, ENC_NA); offset += 1;
	proto_tree_add_item(enetCommandHeader, hf_enet_channelId, tvb, offset, 1, ENC_NA); offset += 1;
	proto_tree_add_item(enetCommandHeader, hf_enet_sequenceNumber, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
	return offset;
}
static guint dissect_lolPacket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *enetTree, guint offset)
{
	proto_item *lolNode = NULL;
	proto_tree *lolTree = NULL;
	proto_item *packetItem = NULL;
	guint16 dataLength = 0;
	guint16 encLength = 0;
	guint length;
	

	length = tvb_length(tvb);
	dataLength = tvb_get_ntohs(tvb, offset);
	encLength = dataLength-(dataLength%8);

	/* Create a subnode for this package */
	lolNode = proto_tree_add_item(enetTree, proto_lol, tvb, offset, 4+dataLength, FALSE);
	lolTree = proto_item_add_subtree(lolNode, ett_lol);

	/* Format info for the header for this package */
	proto_tree_add_item(lolTree, hf_lol_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
	
	if(encLength > 0)
		if(isKey)
		{

			int i = 0;
			BLOWFISH_context c;
			guchar *decrypted, *packetData;
			tvbuff_t *new_tvb;
			

			decrypted = (guchar*)g_malloc(dataLength);
			packetData = (guchar*)tvb_get_ptr(tvb, offset, dataLength);

			bf_setkey(&c, key, (unsigned)16);

			while(i < encLength)
			{
				decrypt_block(&c, (byte*)&decrypted[i], (byte*)&packetData[i]);
				i+=8;
			}
			memcpy(&decrypted[i], &packetData[i], (dataLength%8)); //Copy remained unencrypted bytes

			new_tvb = tvb_new_real_data(decrypted, dataLength, dataLength);
			tvb_set_child_real_data_tvbuff(tvb, new_tvb);
			add_new_data_source(pinfo, new_tvb, "Decrypted");

			proto_tree_add_item(lolTree, hf_lol_packet, new_tvb, 0, dataLength, ENC_NA); //Add extra view with decrypted bytes
		}
	else
		if(length >= offset+dataLength)
			packetItem = proto_tree_add_item(lolTree, hf_lol_packet, tvb, offset, dataLength, ENC_NA);

	offset += dataLength;
	return offset;
}

static guint dissect_enet_sendReliable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *enetTree, ENetProtocol *command, guint offset)
{
	offset = dissect_lolPacket(tvb, pinfo, enetTree, offset);
	return offset;
}

static guint dissect_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *enetTree, unsigned char *enetData, guint offset)
{
	ENetProtocol * command;
	guint length = tvb_length(tvb);

	command = (ENetProtocol *)( enetData+offset);
	offset = dissect_enet_commandHeader(tvb, pinfo, enetTree, command, offset);
	switch (command->header.command & ENET_PROTOCOL_COMMAND_MASK)
	{
		case ENET_PROTOCOL_COMMAND_ACKNOWLEDGE:
			col_append_str(pinfo->cinfo, COL_INFO, "Ack, ");
			break;
		case ENET_PROTOCOL_COMMAND_CONNECT:
			col_append_str(pinfo->cinfo, COL_INFO, "Connect, ");
			break;
		case ENET_PROTOCOL_COMMAND_VERIFY_CONNECT:
			col_append_str(pinfo->cinfo, COL_INFO, "Check Connect, ");
			break;
		case ENET_PROTOCOL_COMMAND_DISCONNECT:
			col_append_str(pinfo->cinfo, COL_INFO, "Disconnect, ");
			break;

		case ENET_PROTOCOL_COMMAND_PING:
			col_append_str(pinfo->cinfo, COL_INFO, "Ping, ");
			break;

		case ENET_PROTOCOL_COMMAND_SEND_RELIABLE:
			offset = dissect_enet_sendReliable(tvb, pinfo, enetTree, command, offset);
			if(length >= offset+sizeof(ENetProtocolCommandHeader))
				offset = dissect_command(tvb, pinfo, enetTree, enetData, offset);
			col_append_str(pinfo->cinfo, COL_INFO, "Send reliable, ");
			break;

		case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE:
			col_append_str(pinfo->cinfo, COL_INFO, "Send unreliable, ");
			break;

		case ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
			col_append_str(pinfo->cinfo, COL_INFO, "Send unsequenced, ");
			break;

		case ENET_PROTOCOL_COMMAND_SEND_FRAGMENT:
			col_append_str(pinfo->cinfo, COL_INFO, "Send fragment, ");
			break;

		case ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT:
			col_append_str(pinfo->cinfo, COL_INFO, "Bandwidth limit, ");
			break;

		case ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE:
			col_append_str(pinfo->cinfo, COL_INFO, "Throttle configure, ");
			break;

		case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
			col_append_str(pinfo->cinfo, COL_INFO, "Unreliable fragment, ");
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, "Unknown, ");
	}
	return offset;
}

static void dissect_lol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	//Enet
	unsigned char *enetData = NULL;
	ENetProtocolHeader * header;
	
	size_t headerSize;
	enet_uint32 checksum;
	enet_uint16 peerID, flags;
	enet_uint8 sessionID;
	guint offset = 0;


	/* Clear out stuff in the info column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoL");
	col_clear(pinfo->cinfo, COL_INFO);
	
	if(tree)
	{
		proto_item *enetNode = NULL;
		proto_item *enetHeader = NULL, *item = NULL;
		proto_tree *enetTree = NULL;
		

		enetData = (unsigned char*)tvb_get_ptr(tvb, 0, tvb_length(tvb));
		header = (ENetProtocolHeader *)enetData;
		peerID = ENET_NET_TO_HOST_16 (header -> peerID);
		sessionID = (peerID & ENET_PROTOCOL_HEADER_SESSION_MASK) >> ENET_PROTOCOL_HEADER_SESSION_SHIFT;
		flags = peerID & ENET_PROTOCOL_HEADER_FLAG_MASK;
		peerID &= ~ (ENET_PROTOCOL_HEADER_FLAG_MASK | ENET_PROTOCOL_HEADER_SESSION_MASK);
		headerSize = (flags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME ? sizeof (ENetProtocolHeader) : (size_t) & ((ENetProtocolHeader *) 0) -> sentTime);
		headerSize += sizeof (enet_uint32); //As LoL using checksum (and i think there checksum is always returning zero...)
		checksum = ENET_NET_TO_HOST_32(*(enet_uint32 *)&enetData[2]);
		if(checksum != 0)
			headerSize += 2;

		/* Top level header */
		enetNode = proto_tree_add_item(tree, proto_enet, tvb, 0, -1, FALSE);
		enetTree = proto_item_add_subtree(enetNode, ett_enet);
		item = proto_tree_add_item(enetTree, hf_enet_header, tvb, 0, headerSize, FALSE);
		enetHeader = proto_item_add_subtree(item, ett_enet);


		/* Show all the extracted info in the dissector for enet header */
		proto_tree_add_uint(enetHeader, hf_enet_peerId, tvb, offset, 2, peerID);
		proto_tree_add_uint(enetHeader, hf_enet_sessionId, tvb, offset, 2, sessionID);
		proto_tree_add_uint(enetHeader, hf_enet_flags, tvb, offset, 2, flags); offset += 2;
		//proto_tree_add_uint(enetHeader, hf_enet_sentTime, tvb, offset, 2, header->sentTime); offset += 2;
		proto_tree_add_uint(enetHeader, hf_enet_checksum, tvb, offset, 4, checksum);
		proto_tree_add_item(enetHeader, hf_enet_checksum, tvb, offset, 4, FALSE); offset += 4;
		if(checksum != 0)
			 offset += 2;

		offset = dissect_command(tvb, pinfo, enetTree, enetData, offset);

		/*
		if(packet_tracking == 0xFF && packet_function == 0xFF)
		{
			col_append_str(pinfo->cinfo, COL_INFO, "Connection request");
			proto_tree_add_item(lol_tree, hf_lol_data, tvb, offset, -1, FALSE);
			save_key(tvb);
		}				
		else
		{
			gint length = (gint)tvb_length(tvb);
			/* Read all packets *
			while(offset < length)
			{
				guint8 packet_type = tvb_get_guint8(tvb, offset);
				guint8 packet_class = tvb_get_guint8(tvb, offset+1);
								
				guint16 header_length = 4;
				guint16 data_length = 0;
				if((offset+header_length) < length)
					data_length = (guint16)tvb_get_ntohs(tvb, offset+header_length);
				
				//ACK Lenght fixes
				if(packet_type == 0x01)
					data_length = -header_length-3;
				
				switch(packet_type)
				{
					case 0x01:
						col_append_str(pinfo->cinfo, COL_INFO, "Ack, ");
					break;
					case 0x82:
					case 0x83:
						switch(packet_class)
						{
							case 0xFF:
								col_append_str(pinfo->cinfo, COL_INFO, "Connect, ");
							break;
						}
					break;
					
					case 0x86:
						switch(packet_class)
						{
							case 0x00:
								col_append_str(pinfo->cinfo, COL_INFO, "KeyCheck, ");
								if(haveCrc == FALSE)
								{
									checksum = crcsum(0, tvb_get_ptr(tvb, 0, tvb_length(tvb)), tvb_length(tvb));

									p = (char*)g_malloc(255);
									sprintf_s(p, 255, "CRC: %i, (lenght: %i)", checksum, tvb_length(tvb));
									col_append_str(pinfo->cinfo, COL_INFO, p);
									OutputDebugString(p);
									g_free(p);
									haveCrc = TRUE;
								}
							break;
							case 0x05:
								col_append_str(pinfo->cinfo, COL_INFO, "Chat, ");
							break;
						}
				}
				
				/* Packet subtree header *
				/* TODO: Numbering *
				lol_header_item = proto_tree_add_item(lol_tree, hf_lol_packet, tvb, offset, header_length+data_length+2, FALSE);
				lol_header_tree = proto_item_add_subtree(lol_header_item, ett_lol);
				
				/* Packet header structure building *
				proto_tree_add_item(lol_header_tree, hf_lol_type, tvb, offset, 1, FALSE); offset += 1;
				proto_tree_add_item(lol_header_tree, hf_lol_class, tvb, offset, 1, FALSE); offset += 1;
					
				if(packet_type == 0x07 || packet_type == 0x49)
				{
					proto_tree_add_item(lol_header_tree, hf_lol_unknown16, tvb, offset, 2, FALSE); offset += 2; //unk, these two packets randomly have two extra bytes that are always 00
					data_length = (guint16)tvb_get_ntohs(tvb, offset+2);
				}
				
				if(packet_type== 0x83 && packet_class == 0xFF)
				{
					proto_tree_add_item(lol_header_tree, hf_lol_data, tvb, offset, -1, FALSE);
					break;
				}
				else if(packet_type == 0x01)
				{
					proto_tree_add_item(lol_header_tree, hf_lol_unknown16, tvb, offset, 2, FALSE); offset += 2;
					proto_tree_add_item(lol_header_tree, hf_lol_ack, tvb, offset, 2, FALSE); offset += 2;
					proto_tree_add_item(lol_header_tree, hf_lol_acking, tvb, offset, 2, FALSE); offset += 2;
				}
				else
				{
					proto_tree_add_item(lol_header_tree, hf_lol_ack, tvb, offset, 2, FALSE); offset += 2;
					
					if(offset < length)//Lenght check
					{
						proto_tree_add_item(lol_header_tree, hf_lol_length, tvb, offset, 2, FALSE); offset += 2;
						
						if(packet_type== 0x88 && packet_class == 0x03) //Multipacket
						{/*
							if(isKey)
							{
							int i = 0;
							BLOWFISH_context c;					
							guint16 enc_length;*
							
							data_length = (guint16)tvb_get_ntohs(tvb, offset);
							proto_tree_add_item(lol_header_tree, hf_lol_segment_size, tvb, offset, 2, FALSE); offset += 4;
							proto_tree_add_item(lol_header_tree, hf_lol_total_packets, tvb, offset, 2, FALSE); offset += 4;
							proto_tree_add_item(lol_header_tree, hf_lol_sequence, tvb, offset, 2, FALSE); offset += 4;
							proto_tree_add_item(lol_header_tree, hf_lol_total_size, tvb, offset, 2, FALSE); offset += 4;
							proto_tree_add_item(lol_header_tree, hf_lol_previous_size, tvb, offset, 2, FALSE); offset += 2;
							/*
							enc_length = data_length-(data_length%8);
							bf_setkey(&c, key, (unsigned)16);
							while(i < enc_length)
							{
								decrypt_block(&c, (byte*)tvb_get_ptr(tvb, offset+i, 8), (byte*)tvb_get_ptr(tvb, offset+i, 8));
								i+=8;
							}*/
							
							/* The real data *
							proto_tree_add_item(lol_header_tree, hf_lol_data, tvb, offset, data_length, FALSE); offset += data_length;
							//}
						}
						else
						{
						
							if(isKey)
							{
							
							int i = 0;
							BLOWFISH_context c;
							guchar *decrypted;
							tvbuff_t *new_tvb;
							guint16 enc_length = data_length-(data_length%8);
							
							decrypted = (guchar*)g_malloc(enc_length);
							bf_setkey(&c, key, (unsigned)16);
							
							
							while(i < enc_length)
							{
								decrypt_block(&c, (byte*)&decrypted[offset+i], (byte*)tvb_get_ptr(tvb, offset+i, 8));
								i+=8;
							}
							memcpy(&decrypted[offset+i], tvb_get_ptr(tvb, offset+i, 8), (data_length%8));
						
							new_tvb = tvb_new_real_data(decrypted, enc_length, enc_length);
							tvb_set_child_real_data_tvbuff(tvb, new_tvb);
							col_append_str(pinfo->cinfo, COL_INFO, "Decrypted, ");
							add_new_data_source(pinfo, new_tvb, "Decrypted");
		
							proto_tree_add_item(lol_header_tree, hf_lol_data, new_tvb, offset, data_length, FALSE); offset += data_length;
							}
							//proto_tree_add_item(lol_header_tree, hf_lol_data, tvb, offset, data_length, FALSE); offset += data_length;
						}
					}
				}
			}
		}*/
	}
}

tvbuff_t *decrypt_lol(tvbuff_t *tvb, guint16 data_length)
{
	return NULL;
}