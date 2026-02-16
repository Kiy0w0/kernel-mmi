<p align="center">
  <img src="https://img.shields.io/badge/ENGINE-KERNEL%20MANUAL%20MAP-a855f7?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/ARCH-x64%20Ring--0-3b82f6?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/SIGNATURES-RANDOMIZED-f97316?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/OS-Windows%2010%2F11-0ea5e9?style=for-the-badge&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/LICENSE-GPL%20v3-22c55e?style=for-the-badge&labelColor=0d1117" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=800&size=36&duration=3000&pause=1000&color=A855F7&center=true&vCenter=true&width=500&lines=N+A+N+A+H+I+R+A;Kernel+Manual+Map;Ring-0+Injection+%F0%9F%94%AE" alt="Typing" />
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
  <sub>Full kernel-mode PE manual mapping • Zero usermode injection APIs • SharedMemory IPC</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-00599C?style=flat&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows%20Driver%20Kit-0078D4?style=flat&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Visual%20Studio%202022-5C2D91?style=flat&logo=visualstudio&logoColor=white" />
  <img src="https://img.shields.io/badge/x64-Kernel%20Mode-ef4444?style=flat" />
</p>

---

## 🔮 What is Nanahira?

**Nanahira** is a **ring-0 kernel manual map** DLL injection engine. The entire injection process — PE header parsing, section mapping, base relocations, import resolution, memory protection, and `DllMain` execution — happens **entirely inside the Windows kernel**.

The usermode component (`nanahira.exe`) only does two things: reads the DLL file from disk and writes it to a shared memory section. **Zero injection APIs are called from usermode.** The kernel driver handles everything else.

### How It Works

| Component | Role |
|:---|:---|
| `driver.sys` | Ring-0 engine — performs full PE manual map in kernel space |
| `nanahira.exe` | Ring-3 client — reads DLL, writes to shared memory, displays UI |
| Shared Memory | 16 MB named section — invisible IPC, no IOCTLs or device objects |

### vs Standard Injection

| | **Nanahira** | **Standard Injectors** |
|:---|:---:|:---:|
| Injection APIs from usermode | **❌ Zero** | ✅ VirtualAllocEx, WriteProcessMemory, etc. |
| PE operations location | **Ring 0** (kernel) | Ring 3 (usermode) |
| IPC method | **SharedMemory** (invisible) | IOCTLs / DeviceIoControl |
| Module list entries | **None** (manual map) | Visible via LDR |
| Binary uniqueness per build | **✅ Fully automatic** | ❌ Same hash every time |
| Binary hash matching | **❌ Unique hash every build** | Easily fingerprinted |

---

## ✨ Features

| | Feature | Description |
|:---:|:---|:---|
| 🧠 | **Full Kernel Manual Map** | PE parsing, section mapping, relocations, import resolution, entry point — all in ring 0 |
| 🔒 | **SharedMemory IPC** | No IOCTLs, no device objects — named kernel section only |
| 🎭 | **2-Layer Signature Engine** | Source-level mutation + binary PE mutation = unique fingerprint every build |
| 🎨 | **Gradient Console UI** | 24-bit TrueColor ANSI console with animated progress bars |
| 👻 | **Ghost Mode** | Zero usermode injection APIs — zero traces |
| ⚡ | **Fast Injection** | Full manual map completes in milliseconds |
| 🛡️ | **Header Erasure** | PE headers wiped from target process after mapping |
| 🔄 | **Quick Re-Spoof** | One-click binary re-mutation without recompiling |

---

## 📁 Project Structure

```
nanahira/
│
├── 📄  nanahira.sln              VS2022 Solution
├── 🔨  build_release.bat         Full 5-step build pipeline
├── ⚡  quick_spoof.bat           One-click binary re-spoof
├── 📖  README.md                 This file
├── 🚫  .gitignore
│
├── driver/                       Kernel Driver (WDM)
│   ├── driver.vcxproj            VS2022 project
│   ├── driver.cpp                Manual map engine (~1100 lines)
│   └── driver.h                  Internal header + dynamic imports
│
├── usermode/                     Usermode Injector
│   ├── usermode.vcxproj          VS2022 project
│   ├── nanahira.cpp              Injector + UI (~520 lines)
│   └── nanahira.h                Utilities header
│
├── shared/
│   └── protocol.h                IPC protocol (shared KM/UM)
│
├── tools/
│   ├── source_randomizer.ps1     Source-level mutation engine
│   └── signature_randomizer.ps1  Binary PE mutation engine (10 mutations)
│
└── output/                       ← Generated after build
    ├── driver.sys
    └── nanahira.exe
```

---

## ⚙️ Requirements

| Requirement | Details | Get It |
|:---|:---|:---|
| **Windows 10/11 x64** | Tested on Win11 25H2 | — |
| **Administrator** | Everything needs elevation | Right-click → Run as admin |
| **Visual Studio 2022** | With **"Desktop development with C++"** | [Download](https://visualstudio.microsoft.com/downloads/) |
| **Windows Driver Kit (WDK)** | Matching your Windows SDK version | [Download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) |
| **PowerShell 7+** | For signature randomization engine | [Install](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows) |

<details>
<summary><b>📋 Installation Guide</b></summary>

### Visual Studio 2022 + WDK

1. Install **Visual Studio 2022** (Community is free)
2. In VS Installer → Workloads → check **"Desktop development with C++"**
3. Install the **Windows Driver Kit (WDK)**: [Download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
4. Make sure WDK version matches your Windows SDK version

</details>

---

## 🚀 Usage

### 📌 Follow This Exact Order

```
  ① BUILD  →  ② LOAD DRIVER  →  ③ LAUNCH TARGET  →  ④ INJECT
```

### ① Build Your Unique Binaries

> ⚠️ Run as Administrator

**Option A — Full Build Pipeline (recommended):**
```batch
cd nanahira
build_release.bat
```

| Step | What Happens |
|:---:|:---|
| **1/5** | 🎭 Randomizes identifiers in source code |
| **2/5** | 🔧 Compiles `driver.sys` with unique values |
| **3/5** | 🔧 Compiles `nanahira.exe` with matching values |
| **4/5** | 🔄 Restores source to original |
| **5/5** | 🎭 Applies 10 PE mutations to both binaries |

**Result:** `output/driver.sys` + `output/nanahira.exe` with completely unique SHA256 hashes.

> 💡 Every run = different machine code + different binary signatures.

**Option B — Visual Studio:**
1. Open `nanahira.sln` in VS2022
2. Set configuration to `Release | x64`
3. Build → Build Solution (`Ctrl+Shift+B`)
4. Run `quick_spoof.bat` to apply binary mutations

Output: `output/driver.sys` + `output/nanahira.exe`

### ② Load the Driver

**Method A — Test Signing (recommended):**

> Requires **Secure Boot** disabled in BIOS and **test signing** enabled.

```batch
:: One-time setup (run as Administrator, then reboot)
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```

After reboot, sign and load the driver:
```powershell
# Create test certificate (PowerShell as Admin, one-time only)
$cert = New-SelfSignedCertificate -Subject "CN=Nanahira Test" -Type CodeSigningCert -CertStoreLocation "Cert:\LocalMachine\My"

# Add to trusted stores
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$store.Open("ReadWrite"); $store.Add($cert); $store.Close()
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher","LocalMachine")
$store.Open("ReadWrite"); $store.Add($cert); $store.Close()

# Sign the driver
Set-AuthenticodeSignature -FilePath "output\driver.sys" -Certificate $cert
```

```batch
:: Load driver
sc create nanahira type= kernel binPath= "C:\full\path\to\output\driver.sys"
sc start nanahira
```

> Look for: `STATE: 4  RUNNING` → ✅ ready

**Method B — kdmapper:**
```batch
kdmapper.exe output\driver.sys
```

> ⚠️ kdmapper may cause BSOD on some systems. Test signing is safer.

> Look for: `[+] Driver mapped successfully` → ✅ ready

### ③ Launch Target Application

Open your target and wait until fully loaded.

### ④ Inject

```batch
:: Command-line mode
output\nanahira.exe <process_name> <path_to_dll>

:: Interactive mode (follow prompts)
output\nanahira.exe
```

### ⚡ Re-Spoof Without Rebuilding

```batch
quick_spoof.bat
```

Instantly re-mutates binaries with new signatures — no recompilation needed.

> ⚠️ After re-spoofing, you need to **re-sign** `driver.sys` before loading.

### 🔄 Unload Driver

```batch
sc stop nanahira
sc delete nanahira
```

---

## 🏗️ Architecture

```
  ┌─────────────────────┐                              ┌──────────────────────────┐
  │                     │    Shared Memory (16MB)       │                          │
  │   nanahira.exe      │ ════════════════════════════► │   driver.sys             │
  │   Ring 3 / User     │   DLL bytes + target PID      │   Ring 0 / Kernel        │
  │                     │ ◄════════════════════════════ │                          │
  │  • Find process     │   Status + Progress + Base    │  • Parse PE headers      │
  │  • Read DLL file    │                              │  • Allocate memory       │
  │  • Write to SHM     │                              │  • Map sections          │
  │  • Display UI       │                              │  • Fix relocations       │
  │                     │                              │  • Resolve imports       │
  │                     │                              │  • Set protections       │
  │  APIs used:         │                              │  • Erase PE headers      │
  │  OpenFileMappingA   │                              │  • Call DllMain          │
  │  MapViewOfFile      │                              │                          │
  └─────────────────────┘                              └──────────────────────────┘
```

---

## 🔧 Troubleshooting

<details>
<summary><b>🔨 Build Errors</b></summary>

| Error | Fix |
|:---|:---|
| `Visual Studio 2022 not found!` | Install VS2022 + **"Desktop development with C++"** |
| `WDK not found` | Install [WDK 10](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) |
| `'cl.exe' not recognized` | Use **"x64 Native Tools Command Prompt"** or let build script handle it |
| `ExAllocatePoolWithTag deprecated` | Already replaced with `ExAllocatePool2` — rebuild |
| `LNK2001 unresolved external` | Undocumented APIs resolved dynamically via `MmGetSystemRoutineAddress` |

</details>

<details>
<summary><b>🔌 Driver Loading</b></summary>

| Error | Fix |
|:---|:---|
| `Access denied` | **Run as Administrator** |
| `StartService FAILED 577` | Driver is unsigned — use test signing + self-signed certificate (see Usage section) |
| `Vulnerable driver list blocked` | Set registry: `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config` → `VulnerableDriverBlocklistEnable` = `0` |
| `Value protected by Secure Boot` | Disable **Secure Boot** in BIOS first, then enable test signing |
| `Memory Integrity blocking` | Disable via **Windows Security → Device Security → Core Isolation → Memory integrity → Off** |
| `Failed to load vulnerable driver` (kdmapper) | Use **test signing method** instead of kdmapper |
| `Driver already loaded` | Run `sc stop nanahira` then `sc delete nanahira` first |
| BSOD after kdmapper | kdmapper exploit failed — use test signing method instead |

</details>

<details>
<summary><b>💉 Injection Issues</b></summary>

| Error | Fix |
|:---|:---|
| `Cannot connect` | Load driver first (see ② Load the Driver) |
| `Process not found` | Target must be running |
| `Invalid PE` | Make sure you're injecting a valid x64 DLL |
| `Import resolution failed` | DLL may depend on modules not loaded in target |
| Target crashes after injection | DLL is incompatible with current target version (check Event Viewer → `0xC0000005` = access violation in DLL) |

</details>

---

## 🎭 Signature Randomization Engine

### Layer 1 — Source Mutation (Before Compilation)

Mutates identifiers in `protocol.h` before `cl.exe` compiles, making the actual machine code different:

| What Gets Randomized | Example |
|:---|:---|
| Shared memory section name | `SharedMapSec` → `xKpLmNqRwY` |
| Magic handshake value | `0x4D505348` → `0xA7F3B2C1` |
| Pool tag | `'pMhS'` → `'qZxW'` |

### Layer 2 — Binary PE Mutation (After Compilation)

10 mutations applied to the compiled `.sys` and `.exe`:

| # | Mutation | What It Does |
|:---:|:---|:---|
| 1 | **TimeDateStamp** | Randomizes compile timestamp |
| 2 | **Checksum** | Randomizes PE checksum |
| 3 | **Rich Header** | Destroys MSVC fingerprint |
| 4 | **Section Names** | `.text`→`.code`, `.rdata`→`.cnst`, etc. |
| 5 | **Debug Directory** | Wipes all PDB paths and CodeView GUIDs |
| 6 | **Linker Version** | Fakes MSVC linker version |
| 7 | **OS Version** | Randomizes minimum OS version |
| 8 | **Polymorphic Junk** | Fills code caves with NOP-like patterns |
| 9 | **Build GUID** | Stamps unique 128-bit watermark |
| 10 | **DOS Stub** | Randomizes unused DOS header bytes |

### Proof — Every Spoof = Different Hash

```
Run 1:  CFD54215EF00E743182950F050182E95D11056487E7B0C2F4B00294E7800777A
Run 2:  2BA928715B4795075D802702B730F7476F4B425295B4C0D4B11B7E1906923C56
Run 3:  0F53D2E9CE5D91283A2AB63695F87FB002B391EB1B0EE13D8061223CC5FFEE0A
```

---

## ⚖️ Disclaimer

This project is for **educational and research purposes only**. The author is not responsible for any misuse. Use at your own risk and in compliance with applicable laws and terms of service.

---

<p align="center">
  <b>N A N A H I R A</b><br>
  <sub><i>Kernel Manual Map Injection Engine</i></sub><br><br>
  <img src="https://img.shields.io/badge/Made%20with-💜-a855f7?style=flat&labelColor=0d1117" />
  <img src="https://img.shields.io/badge/by-Kiy0w0-3b82f6?style=flat&labelColor=0d1117" />
</p>
