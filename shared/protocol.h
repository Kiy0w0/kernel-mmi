#pragma once

#ifndef SHARED_PROTOCOL_H
#define SHARED_PROTOCOL_H

#define INJECTOR_PROCESS_NAME   L"nanahira.exe"

#define PROTO_MAGIC             0x4D505348

#define DRV_POOL_TAG            'pMhS'

#define SHM_TOTAL_SIZE          (16 * 1024 * 1024)

#define MAX_PAYLOAD_SIZE        (15 * 1024 * 1024)

#define POLL_TIMEOUT_MS         10000

#define PROTO_VER_MAJOR         1
#define PROTO_VER_MINOR         0

typedef enum _IPC_COMMAND {
    IPC_CMD_NONE        = 0,
    IPC_CMD_INJECT      = 1,
    IPC_CMD_PING        = 2,
    IPC_CMD_CLEANUP     = 3,
    IPC_CMD_STATUS      = 4,
} IPC_COMMAND;

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

#pragma pack(push, 8)

typedef struct _SHARED_HEADER {

    unsigned int        Magic;
    unsigned int        Version;

    volatile long       Command;
    volatile long       Status;

    unsigned int        TargetPid;
    unsigned int        PayloadSize;
    unsigned int        Flags;
    unsigned int        _reserved;

    unsigned long long  BaseAddr;

    volatile long       Progress;
    char                Message[128];

    unsigned char       _pad[84];

} SHARED_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(SHARED_HEADER) == 256, "Header must be 256 bytes");
#endif

#define PAYLOAD_DATA_OFFSET     sizeof(SHARED_HEADER)

#endif

