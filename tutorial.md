# Nanahira Usage Tutorial

This guide walks you through building, loading, and using the Nanahira kernel manual mapping injector.

---

## Order of Operations

```
  1. Build  →  2. Load driver  →  3. Start target  →  4. Inject
```

---

## 1. Build

### Prerequisites
* **Rust & Cargo:** The build process uses a Rust PDB offset parser to dynamically resolve kernel offsets.
* **WDK & SDK:** Ensure you have the matching Windows Driver Kit and SDK installed.

To build the project automatically:

```batch
build_release.bat
```

This runs the Rust PDB offset parser to generate `offsets.h`, executes the source mutation tool, compiles both projects under Visual Studio, restores the source files, and applies 10 binary PE mutations. The final outputs will be placed in the `output/` directory.

Alternatively, if you build manually inside Visual Studio 2022 under `Release | x64`, the Pre-Build Event will automatically run `cargo run --manifest-path "tools\pdb-parser\Cargo.toml" --release` to generate the correct offsets. Then execute `quick_spoof.bat` to apply the binary PE mutations.

---

The driver (`driver.sys`) needs to be loaded into the kernel.

### Option A: Test Signing (Recommended for Dev & Stability)

1. **One-time setup:** Run the following commands as Administrator and reboot your PC:
   ```batch
   bcdedit /set testsigning on
   bcdedit /set nointegritychecks on
   ```

2. **Self-sign the driver:** Run this PowerShell block as Administrator to generate a local cert and sign the binary:
   ```powershell
   # Self-sign the driver
   $cert = New-SelfSignedCertificate -Subject "CN=Nanahira" -Type CodeSigningCert -CertStoreLocation "Cert:\LocalMachine\My"
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
   $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher","LocalMachine")
   $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
   Set-AuthenticodeSignature -FilePath "output\driver.sys" -Certificate $cert
   ```

3. **Register and Start the Service:**
   ```batch
   sc create nanahira type= kernel binPath= "C:\path\to\output\driver.sys"
   sc start nanahira
   ```

### Option B: Vulnerable Driver Mapping (BYOVD Bypass - No Test Signing Required)

For production environments where Test Signing mode cannot be enabled, use the custom `vuln-loader` tool to temporarily disable DSE (Driver Signature Enforcement) and load `driver.sys`.

1. **Prerequisite:** Download a signed copy of `RTCore64.sys` (MSI vulnerable driver).
2. **Build the loader:**
   ```batch
   cd tools\vuln-loader
   cargo build --release
   ```
3. **Execute the bypass:** Run as Administrator:
   ```batch
   target\release\vuln-loader.exe C:\path\to\RTCore64.sys C:\path\to\output\driver.sys
   ```

This will load `RTCore64.sys`, locate the `g_CiOptions` kernel variable, temporarily set it to `0` (DSE disabled), load the unsigned `driver.sys`, restore `g_CiOptions` back to its original value, and clean up the MSI driver.

---

## 3. Inject

Once the driver is active, you can launch the injector. Specify your target process and DLL path:

```batch
:: Default kernel manual mapping mode
output\nanahira.exe target.exe C:\path\to\dll.dll

:: Thread hijack mode (hijacks an existing thread; no new threads created)
output\nanahira.exe target.exe C:\path\to\dll.dll --hijack

:: WinEventHook injection mode (no CreateRemoteThread)
output\nanahira.exe target.exe C:\path\to\dll.dll --mode=hook

:: Usermode fallback injection mode (no driver required)
output\nanahira.exe target.exe C:\path\to\dll.dll --mode=usermode

:: GUI/CLI Mode
output\nanahira.exe
```

---

## 4. Re-spoof Binaries

To apply fresh PE binary mutations without recompiling the source code:

```batch
quick_spoof.bat
```
*(Make sure to re-sign `driver.sys` after running this).*

---

## Unload Driver

To stop and remove the registered kernel service safely:

```batch
sc stop nanahira
sc delete nanahira
```

---

## Injection Flags

Per-injection behavior can be controlled via flags defined in `shared/protocol.h`:

| Flag | Effect |
|:---|:---|
| `INJ_FLAG_ERASE_HEADERS` | Zero out PE headers in the target process after mapping |
| `INJ_FLAG_STOMP_HEADERS` | Overwrite PE headers with LFSR junk instead of zeros |
| `INJ_FLAG_SKIP_TLS` | Skip execution of TLS callbacks |
| `INJ_FLAG_SKIP_EXCEPTIONS` | Skip `RtlAddFunctionTable` exception directory call |
| `INJ_FLAG_THREAD_HIJACK` | Hijack an existing thread to execute the entry point |
