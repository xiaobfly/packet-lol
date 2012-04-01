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
 
#include "define.h"
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#undef UNICODE
#undef _UNICODE

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/frame_data.h>

#include <stdio.h>
#include <stdlib.h>
#include <process.h>

#pragma comment(lib, "wsock32.lib")
#include <winsock2.h>
#include <Windows.h>
#include <tlhelp32.h>

#include "lol.h"

/* Special CRC */
static guint16 crcsum(guint16 crc, const guint8* message, guint length);

static gboolean haveCrc = FALSE;
static gboolean initialized = FALSE;

/* Listener system */
static gboolean dbg_stop = FALSE;
static HANDLE event_dbr, event_ddr, mapping;
static HANDLE dbg_thread = NULL;
struct dbwin_buffer *dbg;
static base64_decodestate base64;
static byte key[16];
static gboolean isKey = FALSE;

/* Handlers */
static gint ett_lol = -1;
static int proto_lol = -1;
static dissector_handle_t lol_handle;

/* Structure */
static int hf_lol_packet = -1;
static int hf_lol_unknown16 = -1;

static int hf_lol_magic = -1;
static int hf_lol_tracking = -1;
static int hf_lol_function = -1;
static int hf_lol_unique = -1;
static int hf_lol_type = -1;
static int hf_lol_class = -1;
static int hf_lol_length = -1;
static int hf_lol_data = -1;
static int hf_lol_ack = -1;
static int hf_lol_acking = -1;

static int hf_lol_segment_size = -1;
static int hf_lol_total_packets = -1;
static int hf_lol_sequence = -1;
static int hf_lol_total_size = -1;
static int hf_lol_previous_size = -1;

/* Global sample preference ("controls" display of numbers) */
static guint8 *gPREF_KEY = NULL;
static guint gPREF_PORT = 5000;

#define LOL_ACK_FLAG 0x01
void proto_register_lol(void)
{
	module_t *lol_module;
	
	static hf_register_info hf[] = {
		{ &hf_lol_magic,
			{ "Magic number", "lol.magic",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_tracking,
			{ "Tracking", "lol.tracking",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_function,
			{ "Function", "lol.function",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_unique,
			{ "Unique number", "lol.unique",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_packet,
			{ "Packet", "lol.packet",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_type,
			{ "Type", "lol.type",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_class,
			{ "Class", "lol.class",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_unknown16,
			{ "Unknown 16", "lol.unknown16",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_length,
			{ "Length", "lol.length",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_data,
			{ "Data", "lol.data",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_ack,
			{ "Ack", "lol.ack",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_acking,
			{ "Acking", "lol.acking",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_segment_size,
			{ "Segment size", "lol.segment_size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_total_packets,
			{ "Total packets", "lol.total_packets",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_sequence,
			{ "Sequence number", "lol.sequence",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_total_size,
			{ "Total size", "lol.total_size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lol_previous_size,
			{ "Previous size", "lol.previous_size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		}
	};
	
	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_lol
	};
		
	proto_lol = proto_register_protocol(
		"League of Legends GC Protocol",	/* name */
		"LOL",								/* short name */
		"lol"								/* abbrev */
	);
	
	proto_register_field_array(proto_lol, hf, array_length(hf));
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

void parse_cmd(HANDLE handle)
{
	int i = 0;
	int peb_address;
	int rtl_user_proc_params_address;
	UNICODE_STRING command_line_struct;
	gchar *command_line, *p, *t;
		
	peb_address = GetPebAddress(handle);
	ReadProcessMemory(handle, (char*)peb_address + 0x10, &rtl_user_proc_params_address, sizeof(int), NULL);
	ReadProcessMemory(handle, (char*)rtl_user_proc_params_address + 0x40, &command_line_struct, sizeof(command_line_struct), NULL);
	command_line = g_malloc(command_line_struct.Length);
	ReadProcessMemory(handle, command_line_struct.Buffer, command_line, command_line_struct.Length, NULL);
	
	inplace_to_ascii(command_line, command_line_struct.Length);
	
	//Extraction
	command_line[strlen(command_line)-2] = '\0'; //Remove last "
	p = strrchr(command_line, '"');
	p = strchr(p, ' ')+1; p[4] = '\0';
	OutputDebugString(p);
	gPREF_PORT = atoi(p); p+=5;
	t = strchr(p, ' '); t[0] = '\0';
	memcpy(gPREF_KEY, p, strlen(p)+1);
	g_free(command_line);
	
	//Port setting
	set_single_port(gPREF_PORT);
	
	//Key decrypting
	base64_init_decodestate(&base64);
	base64_decode_block(gPREF_KEY, (int)strlen(gPREF_KEY), key, &base64);
	isKey = TRUE;
	OutputDebugString(gPREF_KEY);
}

typedef struct _dummy_key
{
	guint32 x;
	guint32 y;
	guint32 length;
	guint32 length_;
	guint8 macs[6];
	guint8 macd[6];
	guint16 size;
	guint8 key[32];
} dummy_key;

dummy_key make_dummy_key(guint8 *key)
{
	guint16 length = strlen(key);
	dummy_key packet;
	
	packet.size = packet.length = packet.length_ = length;
	memcpy(packet.key, key, length);
	
	return packet;
}

void save_key(tvbuff_t *tvb)
{
	char *buf;
	int sock, ret;
	gint length;
	struct sockaddr_in address; 
	dummy_key dummy;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	
	address.sin_family = AF_INET;
	address.sin_port = 5150; //tvb_get_ntohs(tvb, 34);
	address.sin_addr.s_addr = inet_addr("192.168.2.202"); //tvb_get_ipv4(tvb, 26);
	
	length = (gint)tvb_length(tvb);
	buf = (char*)g_malloc(255);
	//tvb_memcpy(tvb, buf, 0, length);
	
	//Get ip4
	//tvb_get_ipv4(tvb, 26); Get source ip
	//tvb_get_ntohs(tvb, 34); Get source port
	
	dummy = make_dummy_key(gPREF_KEY);
	
	ret = sendto(sock, (char*)&dummy, dummy.size, 0, (struct sockaddr *)&address, sizeof(address));
	sprintf_s(buf, 255, "Packet(%i), port %i(%x), addr %s(%X), dummy length: %i", ret, address.sin_port, tvb_get_ntohs(tvb, 34), inet_ntoa(address.sin_addr), tvb_get_guint8(tvb, 26), dummy.size);
	
	
	OutputDebugString(buf);
	g_free(buf);
}

void inplace_to_ascii(char* unicode, int length)
{
	int i, x;
	for(i = 2, x = 1; i < length; i+=2, x++)
		unicode[x] = unicode[i];
}

void dbg_listener_thread(void *thread_parameter)
{
	HANDLE gc_handle;
	
	while(!initialized) //Wait for the dissector to be loaded
		Sleep(50);
		
	while(!dbg_stop)
	{
		gc_handle = getHandleByName(LOL_EXE);
		if(gc_handle != NULL)
		{
			parse_cmd(gc_handle);
			WaitForSingleObject(gc_handle, INFINITE);
			CloseHandle(gc_handle);
		}
		Sleep(SLEEP_TIMEOUT);
	}
}

HANDLE getHandleByName(char *name)
{
	PROCESSENTRY32 entry;
	HANDLE hProcess = NULL;
	HANDLE snapshot = (HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, name) == 0)
			{  
				hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
			}
		}
	}

	CloseHandle(snapshot);
	return hProcess;
}

int GetPebAddress(HANDLE ProcessHandle)
{
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);
    return (int)pbi.PebBaseAddress;
}


void stop_listener(void) 
{
	dbg_stop = TRUE;
	WaitForSingleObject(dbg_thread, INFINITE);
}

void start_listener()
{
	dbg_thread = (HANDLE)_beginthread(dbg_listener_thread, 8192, NULL);
	SetThreadPriority(dbg_thread, THREAD_PRIORITY_TIME_CRITICAL);
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
	OutputDebugString("HANDOFF");
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
static void dissect_lol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	//Enet
	ENetPacket *packet;
	const unsigned char *enetData = NULL;
	ENetProtocolHeader * header;
	ENetProtocol * command;
	//ENetPeer * peer;
	//enet_uint8 * currentData;
	size_t headerSize;
	enet_uint16 peerID, flags;
	enet_uint8 sessionID;
	guint16 checksum;
	char *p = NULL;
	gint offset = 0;
	guint8 packet_tracking = tvb_get_guint8(tvb, 4);
	guint8 packet_function = tvb_get_guint8(tvb, 5);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoL GC");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	//pinfo->fd->flags.visited
	//pinfo->fd->pfd->
	//p = (char*)pinfo->fd->pfd->data;
	//p = (char*)p_get_proto_data(pinfo->fd, 0);
	//printf("Len: %i, Vistied: %i, Byte data: 0x%08X\n", pinfo->fd->cap_len, pinfo->fd->flags.visited, p);
	
	if(tree)
	{
		proto_item *ti = NULL;
		proto_tree *lol_tree = NULL;
		proto_tree *lol_header_tree = NULL;
		proto_item *lol_header_item = NULL;
		
		/* Top level header */
		ti = proto_tree_add_item(tree, proto_lol, tvb, 0, -1, FALSE);
		lol_tree = proto_item_add_subtree(ti, ett_lol);
		
		proto_tree_add_item(lol_tree, hf_lol_magic, tvb, offset, 4, FALSE); offset += 4;
		proto_tree_add_item(lol_tree, hf_lol_tracking, tvb, offset, 1, FALSE); offset += 1;
		proto_tree_add_item(lol_tree, hf_lol_function, tvb, offset, 1, FALSE); offset += 1;
		if(packet_tracking == 0x80)
		{
			proto_tree_add_item(lol_tree, hf_lol_unique, tvb, offset, 2, FALSE); offset += 2;
		}
		
		enetData = tvb_get_ptr(tvb, 0, tvb_length(tvb));
		header = (ENetProtocolHeader *)enetData;
		peerID = ENET_NET_TO_HOST_16 (header -> peerID);
		sessionID = (peerID & ENET_PROTOCOL_HEADER_SESSION_MASK) >> ENET_PROTOCOL_HEADER_SESSION_SHIFT;
		flags = peerID & ENET_PROTOCOL_HEADER_FLAG_MASK;
		peerID &= ~ (ENET_PROTOCOL_HEADER_FLAG_MASK | ENET_PROTOCOL_HEADER_SESSION_MASK);

		headerSize = (flags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME ? sizeof (ENetProtocolHeader) : (size_t) & ((ENetProtocolHeader *) 0) -> sentTime);
		headerSize += sizeof (enet_uint32); //As LoL using checksum (and i think there checksum is always returning zero...)

		if (flags & ENET_PROTOCOL_HEADER_FLAG_COMPRESSED)
		{
			col_append_str(pinfo->cinfo, COL_INFO, "COMPRESSED, ");
		}

		command = (ENetProtocol *)( enetData+headerSize);
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

/* CRC-16 x^16 + x^15 + x^2 + 1
 * Implementation borrowed from the Linux kernel.
 */
static const guint16 crc16_table[256] = {
  0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
  0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
  0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
  0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
  0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
  0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
  0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
  0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
  0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
  0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
  0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
  0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
  0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
  0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
  0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
  0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
  0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
  0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
  0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
  0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
  0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
  0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
  0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
  0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
  0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
  0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
  0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
  0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
  0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
  0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
  0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
  0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static inline guint16 crc16_byte(guint16 crc, const guint8 data)
{
  return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

static guint16
crcsum(guint16 crc, const guint8* buffer, guint len)
{
  while (len--)
    crc = crc16_byte(crc, *buffer++);

  return crc;
}