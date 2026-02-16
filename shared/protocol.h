#pragma once

//=============================================================================
// Shared Protocol Header
// 
// Shared between the kernel driver and usermode injector.
// Defines IPC communication protocol via named shared memory section.
//=============================================================================

#ifndef SHARED_PROTOCOL_H
#define SHARED_PROTOCOL_H

//-----------------------------------------------------------------------------
// Configuration
//-----------------------------------------------------------------------------

// Section name — kernel-mode (NT path)
#define KM_SECTION_PATH         L"\\BaseNamedObjects\\Global\\SharedMapSec"

// Section name — user-mode
#define UM_SECTION_NAME         "Global\\SharedMapSec"

// Handshake magic — verifies shared memory ownership
#define PROTO_MAGIC             0x4D505348  // 'MPSH'

// Kernel pool tag
#define DRV_POOL_TAG            'pMhS'

// Shared memory size (16 MB)
#define SHM_TOTAL_SIZE          (16 * 1024 * 1024)

// Max supported DLL file size (15 MB)
#define MAX_PAYLOAD_SIZE        (15 * 1024 * 1024)

// Usermode poll timeout (ms)
#define POLL_TIMEOUT_MS         10000

// Version info
#define PROTO_VER_MAJOR         1
#define PROTO_VER_MINOR         0

//-----------------------------------------------------------------------------
// Command Codes (usermode -> driver)
//-----------------------------------------------------------------------------
typedef enum _IPC_COMMAND {
    IPC_CMD_NONE        = 0,
    IPC_CMD_INJECT      = 1,
    IPC_CMD_PING        = 2,
    IPC_CMD_CLEANUP     = 3,
} IPC_COMMAND;

//-----------------------------------------------------------------------------
// Status Codes (driver -> usermode)
//-----------------------------------------------------------------------------
typedef enum _IPC_STATUS {
    IPC_IDLE             = 0,
    IPC_READY            = 1,
    IPC_BUSY             = 2,
    IPC_DONE             = 3,
    IPC_ERR_PROCESS      = 10,
    IPC_ERR_ALLOC        = 11,
    IPC_ERR_PE           = 12,
    IPC_ERR_SECTIONS     = 13,
    IPC_ERR_RELOC        = 14,
    IPC_ERR_IMPORTS      = 15,
    IPC_ERR_PROTECT      = 16,
    IPC_ERR_ENTRYPOINT   = 17,
    IPC_ERR_TIMEOUT      = 18,
    IPC_ERR_UNKNOWN      = 99,
} IPC_STATUS;

//-----------------------------------------------------------------------------
// Shared Memory Layout
//
//   [SHARED_HEADER]    256 bytes at offset 0
//   [raw DLL bytes]    starts at offset 256
//
// Flow:
//   1. Driver creates named section, maps it, sets Magic + READY
//   2. Usermode opens section, validates magic
//   3. Usermode writes DLL bytes after header, fills in PayloadSize + PID
//   4. Usermode sets Command = IPC_CMD_INJECT
//   5. Driver picks up command, performs manual map
//   6. Driver writes back Status, BaseAddr
//   7. Usermode polls Status for result
//-----------------------------------------------------------------------------

#pragma pack(push, 8)

typedef struct _SHARED_HEADER {
    // Identification
    unsigned int        Magic;
    unsigned int        Version;

    // IPC
    volatile long       Command;
    volatile long       Status;

    // Injection params (written by usermode)
    unsigned int        TargetPid;
    unsigned int        PayloadSize;

    // Result (written by driver)
    unsigned long long  BaseAddr;

    // Progress
    volatile long       Progress;
    char                Message[128];

    // Padding — keep header at 256 bytes total
    unsigned char       _pad[92];

} SHARED_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(SHARED_HEADER) == 256, "Header must be 256 bytes");
#endif

#define PAYLOAD_DATA_OFFSET     sizeof(SHARED_HEADER)

#endif // SHARED_PROTOCOL_H
