#pragma once
//=============================================================================
// Minimal Discord Rich Presence via Named Pipe (no SDK required)
//=============================================================================

#include <windows.h>

// Call once at startup with your Discord Application ID
// Get one from: https://discord.com/developers/applications
void Discord_Init(const char* applicationId);

// Update the presence display
void Discord_UpdatePresence(
    const char* state,       // e.g. "Idle" or "Injecting..."
    const char* details,     // e.g. "Nanahira Kernel Injector"
    const char* largeImage,  // Large image asset key (or NULL)
    const char* largeText,   // Tooltip for large image (or NULL)
    const char* smallImage,  // Small image asset key (or NULL)
    const char* smallText    // Tooltip for small image (or NULL)
);

// Clean up and disconnect
void Discord_Shutdown(void);
