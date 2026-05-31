<p align="center">
  <img src="https://img.shields.io/badge/ENGINE-KERNEL%20MANUAL%20MAP-a855f7?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/VERSION-3.0.0-22c55e?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/ARCH-x64%20Ring--0-3b82f6?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/SIGNATURES-RANDOMIZED-f97316?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/OS-Windows%2010%2F11-0ea5e9?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/LICENSE-GPL%20v3-22c55e?style=for-the-badge&labelColor=0d1117" />
</p>

<p align="center">
  <img src="sxxi/nanahira.jpg" width="600" alt="Nanahira Header" />
</p>

<p align="center">
  <b>by Kiy0w0</b><br>
  <sub>Full kernel-mode PE manual mapping · Zero usermode injection APIs · MDL Stealth IPC · Thread Hijacking</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-00599C?style=flat&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows%20Driver%20Kit-0078D4?style=flat&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Visual%20Studio%202022-5C2D91?style=flat&logo=visualstudio&logoColor=white" />
  <img src="https://img.shields.io/badge/x64-Kernel%20Mode-ef4444?style=flat" />
</p>

---

## What is Nanahira?

**Nanahira** is a ring-0 kernel manual map DLL injector. Every step of the injection PE parsing, section mapping, base relocations, import resolution, per-section memory protection, TLS callbacks, exception directory registration, and `DllMain` execution runs entirely inside the Windows kernel.

The usermode side (`nanahira.exe`) reads the DLL from disk and drops it into a shared memory section. That's it. No `VirtualAllocEx`, no `WriteProcessMemory`, no `CreateRemoteThread` the kernel driver does all of it.

Three injection modes are available depending on your situation:

| Mode | How it works |
|:---|:---|
| `kernel` | Full ring-0 manual map via driver (default) |
| `hook` | Shellcode injected via `SetWinEventHook` no `CreateRemoteThread` |
| `usermode` | Direct inject without driver `VirtualAllocEx` + self-contained shellcode |

---

## How It Works

```
  nanahira.exe                               driver.sys
  ─────────────                              ─────────────────────────────────
  Find target PID          SharedMemory      Parse PE headers
  Read DLL from disk    ════════════════►    Allocate memory in target
  Write to SHM                               Map sections
  Send IPC command      ◄════════════════    Fix relocations
  Show progress + base    Status / Base      Resolve imports (name + ordinal)
                                             Delay-load imports
                                             Set per-section protections
                                             Register exception table (.pdata)
                                             Run TLS callbacks
                                             Erase / stomp PE headers
                                             Call DllMain
```

The IPC channel between usermode and the kernel driver uses an **anonymous MDL-mapped buffer** no named section objects, no visible handles in the global namespace. The driver auto-maps the buffer into `nanahira.exe` via a process notify callback when the injector starts.

---

## Features

| Feature | Details |
|:---|:---|
| **Ghost Driver** | Unlinks `PsLoadedModuleList` immediately after boot to hide driver from system module enumerators |
| **Self-Erase Header** | Zero-out driver MZ/PE headers from memory inside `DriverEntry` |
| **W^X Execution (No RWX)** | `PAGE_READWRITE` → `PAGE_EXECUTE_READ` promotion in all three injection modes — kernel, hook, and usermode — eliminates RWX pages entirely |
| **Full kernel manual map** | PE ops in ring 0 no usermode injection APIs |
| **Thread hijacking execution** | Hijacks an existing game thread instead of creating a new one avoids `CreateThread` callbacks monitored by Anti-Cheat |
| **Import by name + ordinal** | Both forms handled previously ordinal imports were skipped |
| **Delay-load import support** | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` resolved at inject time |
| **Forwarded export resolution** | Chains like `ntdll.RtlXxx → ntdllp.RtlXxx` are followed |
| **TLS callback execution** | Callbacks run before DllMain, as the loader would |
| **Exception directory (.pdata)** | `RtlAddFunctionTable` called in-process so C++ exceptions / SEH work inside injected DLL |
| **Header erase / stomp** | Zero or LFSR-junk overwrite controlled per-inject via flags |
| **Section name scrubbing** | `.text`, `.rdata` etc. unconditionally zeroed in target after mapping |
| **KEVENT injection mutex** | Prevents concurrent inject races second inject waits up to 5 s before failing |
| **PE deep validator** | Checks `SizeOfImage` bounds and all section `PointerToRawData` offsets before mapping |
| **Worker SEH recovery** | `__try/__except` around worker loop AV in ring-0 resets state instead of BSOD |
| **Stealth IPC** | Anonymous MDL-mapped buffer no named kernel objects visible to scanners |
| **WinEventHook injection** | Alternative entry via `SetWinEventHook` + self-contained shellcode |
| **Usermode fallback** | Works without driver full PE shellcode runs inside target |
| **Compile-time XOR strings** | Sensitive literals encrypted at compile time via template metaprogramming |
| **Signature randomization** | Source-level identifier mutation + binary PE mutations every build |
| **Settings panel (GUI)** | ⚙ button in title bar with Always On Top, GitHub, and Patreon links |
| **VAD node hiding** | Zeroes `StartingVpn` / `EndingVpn` in the target process VAD tree after injection so the region is invisible to `NtQueryVirtualMemory` scanners |
| **Per-section protection** | Hook and usermode modes apply correct per-section page protections after shellcode execution instead of leaving the whole image RWX |
| **`NtCreateThreadEx` hidden thread** | Usermode mode replaces `CreateRemoteThread` with `NtCreateThreadEx` + `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` to bypass thread-creation callbacks |
| **Randomized LFSR seed** | Header stomp junk seed derived from `KeQueryPerformanceCounter` XOR `allocBase` — unique per inject, no static fingerprint |
---

## Project Structure

```
kernel-mmi/
├── nanahira.sln
├── build_release.bat
├── quick_spoof.bat
│
├── driver/
│   ├── driver.cpp          Manual map engine
│   ├── driver.h            Internal declarations + dynamic import typedefs
│   └── offsets.h           Dynamically generated Windows build offsets (PDB parser output)
│
├── usermode/
│   ├── nanahira.cpp        Injector UI + IPC client
│   ├── nanahira.h          Utilities + mode definitions
│   ├── hook_inject.h       WinEventHook injection mode
│   ├── usermode_inject.h   Usermode fallback injection mode
│   ├── xor.h               Compile-time XOR string obfuscation
│   ├── lazy_importer.h     PEB-walk API resolution (LI_FN)
│   ├── discord_rpc.cpp     Discord Rich Presence over named pipe
│   └── discord_rpc.h
│
├── tools/
│   ├── pdb-parser/              Rust-based Windows Kernel PDB offset parsing tool
│   ├── signature_randomizer.ps1 PE binary mutation script
│   └── source_randomizer.ps1   Identifier randomization script
│
└── shared/
    └── protocol.h          Shared memory layout + IPC commands + flags
```

---

## Requirements

| | Details |
|:---|:---|
| Windows 10 / 11 x64 | Tested on 22H2 / 23H2 |
| Administrator | Everything needs elevation |
| Visual Studio 2022 | Desktop development with C++ workload |
| Windows Driver Kit | Match your Windows SDK version |
| Rust & Cargo | Installed on build system (required for pdb-parser) |
| PowerShell 7+ | Required for signature randomization scripts |

---

## Usage

See [tutorial.md](tutorial.md) for full instructions on building, loading the driver, and running the injector.

---

## Signature Randomization

### Layer 1 Source mutation

Before compilation, identifiers in `protocol.h` are randomized shared memory name, magic value, pool tag. The compiled binary contains completely different strings and constants each time.

### Layer 2 Binary PE mutation

After compilation, 10 mutations are applied:

| # | Target | What changes |
|:---:|:---|:---|
| 1 | TimeDateStamp | Random compile timestamp |
| 2 | Checksum | Random PE checksum |
| 3 | Rich header | Destroys MSVC toolchain fingerprint |
| 4 | Section names | `.text` → `.code`, `.rdata` → `.cnst`, etc. |
| 5 | Debug directory | Wipes PDB path and CodeView GUID |
| 6 | Linker version | Fakes MSVC version fields |
| 7 | OS version | Randomizes minimum OS version fields |
| 8 | Code caves | NOP-like junk in padding regions |
| 9 | Build GUID | Unique 128-bit watermark per build |
| 10 | DOS stub | Randomizes unused DOS header bytes |

Every run produces binaries with a different SHA256 hash.

---

## Troubleshooting

<details>
<summary><b>Build errors</b></summary>

| Error | Fix |
|:---|:---|
| `WDK not found` | Install [WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) matching your SDK version |
| `'cl.exe' not recognized` | Use **x64 Native Tools Command Prompt** |
| `LNK2001 unresolved external` | Undocumented APIs are resolved dynamically don't link them statically |

</details>

<details>
<summary><b>Driver loading</b></summary>

| Error | Fix |
|:---|:---|
| `Access denied` | Run as Administrator |
| `StartService FAILED 577` | Driver unsigned enable test signing + self-sign |
| `Value protected by Secure Boot` | Disable Secure Boot in BIOS first |
| `Memory Integrity blocking` | Windows Security → Core Isolation → Memory integrity → Off |
| BSOD on first run | Use test signing with `bcdedit /set testsigning on` and sign driver manually |

</details>

<details>
<summary><b>Injection issues</b></summary>

| Error | Fix |
|:---|:---|
| `Cannot connect` | Driver not loaded run `sc start nanahira` first |
| `Process not found` | Target must already be running |
| `Invalid PE` | Must be a valid x64 DLL |
| `Import resolution failed` | Required DLL not loaded in target try hook or usermode mode |
| Target crashes | Check Event Viewer for `0xC0000005` DLL access violation |

</details>

---

## Changelog

### v3.0.0
- **KEVENT Injection Mutex** Driver uses a `KEVENT` (SynchronizationEvent) so only one injection runs at a time — prevents race conditions and shared memory corruption.
- **Enhanced PE Validator** Validates `SizeOfImage` (max 256 MB) and all section `PointerToRawData` offsets before mapping begins, preventing BSOD from malformed DLLs.
- **Worker Thread SEH Recovery** `__try/__except` wraps the worker switch — an access violation in ring-0 resets state to `IPC_READY` and releases the mutex instead of crashing the kernel.
- **Unconditional Section Name Scrubbing** Section names (`.text`, `.rdata`, etc.) zeroed in target memory after mapping without requiring any flag.
- **PDB Offset Parser** Rust-based build-time symbol parser downloads `ntoskrnl.pdb` from Microsoft symbol servers and auto-generates `offsets.h` to prevent update-induced BSODs.
- **VAD Node Hiding** After injection, `StartingVpn` / `EndingVpn` are zeroed in the target process VAD tree — the allocated region becomes invisible to `NtQueryVirtualMemory`-based scanners.
- **Full W^X Across All Modes** Hook and usermode injection modes now allocate `PAGE_READWRITE`, write shellcode, promote to `PAGE_EXECUTE_READ`, then apply correct per-section protections after execution — no RWX pages at any point.
- **`NtCreateThreadEx` Hidden Thread** Usermode mode replaces `CreateRemoteThread` with `NtCreateThreadEx` + `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER`, bypassing thread-creation callbacks monitored by anti-cheat.
- **Randomized LFSR Stomp Seed** Header stomp junk seed is now derived from `KeQueryPerformanceCounter` XOR `allocBase` per inject — eliminates static binary fingerprint from header stomping.

---

## Credits

Special thanks to the following projects and authors for their contributions to the injection techniques used in this project:

- [TTKKO/Kernel-Manual-Map-Injector](https://github.com/TTKKO/Kernel-Manual-Map-Injector) WinEventHook and shellcode logic.
- [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector) Manual mapping concepts and IAT references.

---

## Disclaimer

For educational and research purposes only. The author takes no responsibility for misuse. Use responsibly and in compliance with applicable laws.

---

<p align="center">
  <b>N A N A H I R A</b><br>
  <sub><i>Kernel Manual Map Injection Engine</i></sub><br><br>
  <img src="https://img.shields.io/badge/Made%20with-💜-a855f7?style=flat&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/by-Kiy0w0-3b82f6?style=flat&labelColor=0d1117" />
</p>
