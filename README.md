<p align="center">
  <img src="https://img.shields.io/badge/ENGINE-KERNEL%20MANUAL%20MAP-a855f7?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/ARCH-x64%20Ring--0-3b82f6?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/SIGNATURES-RANDOMIZED-f97316?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/OS-Windows%2010%2F11-0ea5e9?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/LICENSE-GPL%20v3-22c55e?style=for-the-badge&labelColor=0d1117" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=800&size=36&duration=3000&pause=1000&color=A855F7&center=true&vCenter=true&width=500&lines=N+A+N+A+H+I+R+A;Kernel+Manual+Map;Ring-0+Injection+🔮" alt="Typing" />
</p>

<h3 align="center">
  <code>
    ╔════════════════════════════════════════════════════════════╗<br>
    ║&nbsp;&nbsp; ███╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██╗  ██╗██╗██████╗  █████╗ &nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp; ████╗  ██║██╔══██╗████╗  ██║██╔══██╗██║  ██║██║██╔══██╗██╔══██╗&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp; ██╔██╗ ██║███████║██╔██╗ ██║███████║███████║██║██████╔╝███████║&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp; ██║╚██╗██║██╔══██║██║╚██╗██║██╔══██║██╔══██║██║██╔══██╗██╔══██║&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp; ██║ ╚████║██║  ██║██║ ╚████║██║  ██║██║  ██║██║██║  ██║██║  ██║&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp; ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;║<br>
    ║&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ring-0 Kernel Manual Map DLL Injection Engine&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;║<br>
    ╚════════════════════════════════════════════════════════════╝
  </code>
</h3>

<p align="center">
  <b>by Kiy0w0</b><br>
  <sub>Full kernel-mode PE manual mapping · Zero usermode injection APIs · SharedMemory IPC</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-00599C?style=flat&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows%20Driver%20Kit-0078D4?style=flat&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Visual%20Studio%202022-5C2D91?style=flat&logo=visualstudio&logoColor=white" />
  <img src="https://img.shields.io/badge/x64-Kernel%20Mode-ef4444?style=flat" />
</p>

---

## What is Nanahira?

**Nanahira** is a ring-0 kernel manual map DLL injector. Every step of the injection — PE parsing, section mapping, base relocations, import resolution, per-section memory protection, TLS callbacks, exception directory registration, and `DllMain` execution — runs entirely inside the Windows kernel.

The usermode side (`nanahira.exe`) reads the DLL from disk and drops it into a shared memory section. That's it. No `VirtualAllocEx`, no `WriteProcessMemory`, no `CreateRemoteThread` — the kernel driver does all of it.

Three injection modes are available depending on your situation:

| Mode | How it works |
|:---|:---|
| `kernel` | Full ring-0 manual map via driver (default) |
| `hook` | Shellcode injected via `SetWinEventHook` — no `CreateRemoteThread` |
| `usermode` | Direct inject without driver — `VirtualAllocEx` + self-contained shellcode |

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

The shared memory section (`\BaseNamedObjects\Global\SharedMapSec`) is the only channel between usermode and kernel. No IOCTLs, no device objects.

---

## Features

| Feature | Details |
|:---|:---|
| **Full kernel manual map** | PE ops in ring 0 — no usermode injection APIs |
| **Import by name + ordinal** | Both forms handled — previously ordinal imports were skipped |
| **Delay-load import support** | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` resolved at inject time |
| **Forwarded export resolution** | Chains like `ntdll.RtlXxx → ntdllp.RtlXxx` are followed |
| **TLS callback execution** | Callbacks run before DllMain, as the loader would |
| **Exception directory (.pdata)** | `RtlAddFunctionTable` called so C++ exceptions / SEH work inside injected DLL |
| **Header erase / stomp** | Zero or LFSR-junk overwrite — controlled per-inject via flags |
| **WinEventHook injection** | Alternative entry via `SetWinEventHook` + self-contained shellcode |
| **Usermode fallback** | Works without driver — full PE shellcode runs inside target |
| **Compile-time XOR strings** | Sensitive literals encrypted at compile time via template metaprogramming |
| **Signature randomization** | Source-level identifier mutation + 10 binary PE mutations every build |
| **Discord Rich Presence** | Status updates while injecting |
| **Gradient console UI** | 24-bit ANSI color, live progress bar |

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
│   └── driver.h            Internal declarations + dynamic import typedefs
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
| PowerShell 7+ | Required for signature randomization scripts |

---

## Usage

### Order of Operations

```
  1. Build  →  2. Load driver  →  3. Start target  →  4. Inject
```

### 1. Build

```batch
build_release.bat
```

Runs source mutation, compiles both projects, restores source, then applies 10 binary PE mutations. Output goes to `output/`.

Or build manually in VS2022 `Release | x64`, then run `quick_spoof.bat` for PE mutations.

### 2. Load the Driver

**Test signing (recommended):**

```batch
:: One-time setup — run as admin, then reboot
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```

```powershell
# Self-sign the driver
$cert = New-SelfSignedCertificate -Subject "CN=Nanahira" -Type CodeSigningCert -CertStoreLocation "Cert:\LocalMachine\My"
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$store.Open("ReadWrite"); $store.Add($cert); $store.Close()
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher","LocalMachine")
$store.Open("ReadWrite"); $store.Add($cert); $store.Close()
Set-AuthenticodeSignature -FilePath "output\driver.sys" -Certificate $cert
```

```batch
sc create nanahira type= kernel binPath= "C:\path\to\output\driver.sys"
sc start nanahira
```

**kdmapper:**
```batch
kdmapper.exe output\driver.sys
```

### 3. Inject

```batch
:: Default kernel mode
output\nanahira.exe target.exe C:\path\to\dll.dll

:: WinEventHook mode (no CreateRemoteThread)
output\nanahira.exe target.exe C:\path\to\dll.dll --mode=hook

:: Usermode fallback (no driver needed)
output\nanahira.exe target.exe C:\path\to\dll.dll --mode=usermode

:: Interactive (prompts for process + DLL + mode)
output\nanahira.exe
```

### 4. Re-spoof Binaries

```batch
quick_spoof.bat
```

Applies fresh PE mutations without recompiling. Re-sign `driver.sys` after.

### Unload Driver

```batch
sc stop nanahira
sc delete nanahira
```

### Injection Flags

Per-injection behavior can be controlled via flags set in `shared/protocol.h`:

| Flag | Effect |
|:---|:---|
| `INJ_FLAG_ERASE_HEADERS` | Zero out PE headers in target after mapping |
| `INJ_FLAG_STOMP_HEADERS` | Overwrite headers with LFSR junk instead of zeros |
| `INJ_FLAG_SKIP_TLS` | Skip TLS callback execution |
| `INJ_FLAG_SKIP_EXCEPTIONS` | Skip `RtlAddFunctionTable` call |

---

## Signature Randomization

### Layer 1 — Source mutation

Before compilation, identifiers in `protocol.h` are randomized — shared memory name, magic value, pool tag. The compiled binary contains completely different strings and constants each time.

### Layer 2 — Binary PE mutation

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
| `LNK2001 unresolved external` | Undocumented APIs are resolved dynamically — don't link them statically |

</details>

<details>
<summary><b>Driver loading</b></summary>

| Error | Fix |
|:---|:---|
| `Access denied` | Run as Administrator |
| `StartService FAILED 577` | Driver unsigned — enable test signing + self-sign |
| `Value protected by Secure Boot` | Disable Secure Boot in BIOS first |
| `Memory Integrity blocking` | Windows Security → Core Isolation → Memory integrity → Off |
| BSOD with kdmapper | Use test signing method instead |

</details>

<details>
<summary><b>Injection issues</b></summary>

| Error | Fix |
|:---|:---|
| `Cannot connect` | Driver not loaded — run `sc start nanahira` first |
| `Process not found` | Target must already be running |
| `Invalid PE` | Must be a valid x64 DLL |
| `Import resolution failed` | Required DLL not loaded in target — try hook or usermode mode |
| Target crashes | Check Event Viewer for `0xC0000005` — DLL access violation |

</details>

---

## Credits

Special thanks to the following projects and authors for their contributions to the injection techniques used in this project:

- [TTKKO/Kernel-Manual-Map-Injector](https://github.com/TTKKO/Kernel-Manual-Map-Injector) — WinEventHook and shellcode logic.
- [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector) — Manual mapping concepts and IAT references.

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
