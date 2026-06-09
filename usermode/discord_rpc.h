#pragma once

#include <windows.h>

void Discord_Init(const char* applicationId);

void Discord_UpdatePresence(
    const char* state,
    const char* details,
    const char* largeImage,
    const char* largeText,
    const char* smallImage,
    const char* smallText
);

void Discord_Shutdown(void);
