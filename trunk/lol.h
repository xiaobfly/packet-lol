#define LOL_PORT_MIN 5000
#define LOL_PORT_MAX 5500
#define LOL_EXE "League of Legends.exe"
#define SLEEP_TIMEOUT 50
#define CRC_VER CRC16

#include "blowfish.h"
#include "cdecode.h"
#include "crc.h"
#include <enet\enet.h>

/* forward reference */
void proto_register_lol();
void proto_reg_handoff_lol();
void dissect_lol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_lol(void);
void set_single_port(guint port);

/* Listener */
void start_listener();
void stop_listener(void);
HANDLE getHandleByName(char *name);
void dbg_listener_thread(void *thread_parameter);
int GetPebAddress(HANDLE ProcessHandle);
void inplace_to_ascii(char* unicode, int length);

typedef ULONG (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PROCESS_BASIC_INFORMATION
{
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;