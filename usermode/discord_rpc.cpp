

#include "discord_rpc.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DISCORD_RPC_OPCODE_HANDSHAKE  0
#define DISCORD_RPC_OPCODE_FRAME      1
#define DISCORD_RPC_OPCODE_CLOSE      2
#define DISCORD_RPC_OPCODE_PING       3
#define DISCORD_RPC_OPCODE_PONG       4

#pragma pack(push, 1)
typedef struct {
    DWORD opcode;
    DWORD length;
} DiscordHeader;
#pragma pack(pop)

static HANDLE   g_Pipe         = INVALID_HANDLE_VALUE;
static char     g_AppId[64]    = { 0 };
static __int64  g_StartTime    = 0;
static int      g_NonceCounter = 0;

static void JsonEscapeInto(char* dst, size_t dstSize, const char* src) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dstSize - 2; i++) {
        switch (src[i]) {
        case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
        case '\r': break;
        default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
}

static BOOL SendFrame(DWORD opcode, const char* json) {
    if (g_Pipe == INVALID_HANDLE_VALUE) return FALSE;

    DWORD len = (DWORD)strlen(json);
    DiscordHeader hdr;
    hdr.opcode = opcode;
    hdr.length = len;

    DWORD written = 0;
    if (!WriteFile(g_Pipe, &hdr, sizeof(hdr), &written, NULL)) return FALSE;
    if (!WriteFile(g_Pipe, json, len, &written, NULL)) return FALSE;

    return TRUE;
}

static BOOL ReadFrame(char* buf, DWORD bufSize) {
    if (g_Pipe == INVALID_HANDLE_VALUE) return FALSE;

    DiscordHeader hdr = { 0 };
    DWORD bytesRead = 0;

    if (!ReadFile(g_Pipe, &hdr, sizeof(hdr), &bytesRead, NULL))
        return FALSE;

    if (hdr.length == 0 || hdr.length >= bufSize)
        return FALSE;

    if (!ReadFile(g_Pipe, buf, hdr.length, &bytesRead, NULL))
        return FALSE;

    buf[bytesRead] = '\0';
    return TRUE;
}

static BOOL ConnectPipe(void) {
    char pipeName[64];

for (int i = 0; i < 10; i++) {
        sprintf_s(pipeName, sizeof(pipeName), "\\\\.\\pipe\\discord-ipc-%d", i);

        g_Pipe = CreateFileA(
            pipeName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (g_Pipe != INVALID_HANDLE_VALUE) {

            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(g_Pipe, &mode, NULL, NULL);
            return TRUE;
        }
    }

    return FALSE;
}

void Discord_Init(const char* applicationId) {
    if (!applicationId || !applicationId[0]) return;

    strncpy_s(g_AppId, sizeof(g_AppId), applicationId, _TRUNCATE);
    g_StartTime = (__int64)time(NULL);

if (!ConnectPipe()) {

        return;
    }

char handshake[256];
    sprintf_s(handshake, sizeof(handshake),
        "{\"v\":1,\"client_id\":\"%s\"}", g_AppId);

    if (!SendFrame(DISCORD_RPC_OPCODE_HANDSHAKE, handshake)) {
        CloseHandle(g_Pipe);
        g_Pipe = INVALID_HANDLE_VALUE;
        return;
    }

char response[4096];
    ReadFrame(response, sizeof(response));

}

void Discord_UpdatePresence(
    const char* state,
    const char* details,
    const char* largeImage,
    const char* largeText,
    const char* smallImage,
    const char* smallText)
{
    if (g_Pipe == INVALID_HANDLE_VALUE) return;

    char escState[128] = { 0 };
    char escDetails[128] = { 0 };
    char escLargeImage[128] = { 0 };
    char escLargeText[128] = { 0 };
    char escSmallImage[128] = { 0 };
    char escSmallText[128] = { 0 };

    if (state)      JsonEscapeInto(escState, sizeof(escState), state);
    if (details)    JsonEscapeInto(escDetails, sizeof(escDetails), details);
    if (largeImage) JsonEscapeInto(escLargeImage, sizeof(escLargeImage), largeImage);
    if (largeText)  JsonEscapeInto(escLargeText, sizeof(escLargeText), largeText);
    if (smallImage) JsonEscapeInto(escSmallImage, sizeof(escSmallImage), smallImage);
    if (smallText)  JsonEscapeInto(escSmallText, sizeof(escSmallText), smallText);

char json[2048];
    int pos = 0;

    pos += sprintf_s(json + pos, sizeof(json) - pos,
        "{\"cmd\":\"SET_ACTIVITY\",\"args\":{\"pid\":%lu,\"activity\":{",
        GetCurrentProcessId());

if (details && details[0]) {
        pos += sprintf_s(json + pos, sizeof(json) - pos,
            "\"details\":\"%s\",", escDetails);
    }

if (state && state[0]) {
        pos += sprintf_s(json + pos, sizeof(json) - pos,
            "\"state\":\"%s\",", escState);
    }

pos += sprintf_s(json + pos, sizeof(json) - pos,
        "\"timestamps\":{\"start\":%lld},", g_StartTime);

BOOL hasAssets = (largeImage && largeImage[0]) || (largeText && largeText[0]) ||
                     (smallImage && smallImage[0]) || (smallText && smallText[0]);

    if (hasAssets) {
        pos += sprintf_s(json + pos, sizeof(json) - pos, "\"assets\":{");
        BOOL needComma = FALSE;

        if (largeImage && largeImage[0]) {
            pos += sprintf_s(json + pos, sizeof(json) - pos,
                "\"large_image\":\"%s\"", escLargeImage);
            needComma = TRUE;
        }
        if (largeText && largeText[0]) {
            if (needComma) pos += sprintf_s(json + pos, sizeof(json) - pos, ",");
            pos += sprintf_s(json + pos, sizeof(json) - pos,
                "\"large_text\":\"%s\"", escLargeText);
            needComma = TRUE;
        }
        if (smallImage && smallImage[0]) {
            if (needComma) pos += sprintf_s(json + pos, sizeof(json) - pos, ",");
            pos += sprintf_s(json + pos, sizeof(json) - pos,
                "\"small_image\":\"%s\"", escSmallImage);
            needComma = TRUE;
        }
        if (smallText && smallText[0]) {
            if (needComma) pos += sprintf_s(json + pos, sizeof(json) - pos, ",");
            pos += sprintf_s(json + pos, sizeof(json) - pos,
                "\"small_text\":\"%s\"", escSmallText);
        }
        pos += sprintf_s(json + pos, sizeof(json) - pos, "},");
    }

if (json[pos - 1] == ',') pos--;

g_NonceCounter++;
    pos += sprintf_s(json + pos, sizeof(json) - pos,
        "}},\"nonce\":\"%d\"}", g_NonceCounter);

    SendFrame(DISCORD_RPC_OPCODE_FRAME, json);

char response[4096];
    DWORD available = 0;
    if (PeekNamedPipe(g_Pipe, NULL, 0, NULL, &available, NULL) && available > 0) {
        ReadFrame(response, sizeof(response));
    }
}

void Discord_Shutdown(void) {
    if (g_Pipe != INVALID_HANDLE_VALUE) {

        SendFrame(DISCORD_RPC_OPCODE_CLOSE, "{}");
        CloseHandle(g_Pipe);
        g_Pipe = INVALID_HANDLE_VALUE;
    }
    g_AppId[0] = '\0';
}
