# pdb-parser Rust Kernel Offset Generator

Generates `driver/offsets.h` automatically by downloading the correct
`ntoskrnl.pdb` from Microsoft Symbol Server and extracting struct member
offsets for the current running Windows build.

## Offsets Generated

| Define | Struct | Member |
|:---|:---|:---|
| `OFFSET_EPROCESS_UNIQUEPROCESSID` | `_EPROCESS` | `UniqueProcessId` |
| `OFFSET_EPROCESS_ACTIVEPROCESSLINKS` | `_EPROCESS` | `ActiveProcessLinks` |
| `OFFSET_EPROCESS_IMAGEFILENAME` | `_EPROCESS` | `ImageFileName` |
| `OFFSET_EPROCESS_DEBUGPORT` | `_EPROCESS` | `DebugPort` |
| `OFFSET_EPROCESS_THREADLISTHEAD` | `_EPROCESS` | `ThreadListHead` |
| `OFFSET_EPROCESS_PCB` | `_EPROCESS` | `Pcb` |
| `OFFSET_KTHREAD_STACKBASE` | `_KTHREAD` | `StackBase` |
| `OFFSET_KTHREAD_STACKLIMIT` | `_KTHREAD` | `StackLimit` |
| `OFFSET_KTHREAD_TEB` | `_KTHREAD` | `Teb` |
| `OFFSET_KTHREAD_PROCESS` | `_KTHREAD` | `Process` |
| `OFFSET_KTHREAD_STATE` | `_KTHREAD` | `State` |

## Manual Run

```cmd
cd tools\pdb-parser
cargo run --release
```

## Visual Studio Pre-Build Event (Recommended)

In Visual Studio, open the **driver project** properties:

> **Configuration Properties → Build Events → Pre-Build Event → Command Line**

Paste:
```cmd
cargo run --manifest-path "$(SolutionDir)tools\pdb-parser\Cargo.toml" --release
```

This ensures `driver/offsets.h` is always regenerated with correct offsets
for the current Windows build before the driver is compiled.

## Caching

Downloaded PDB files are cached in `tools/pdb-parser/cache/` and reused
on subsequent builds as long as the Windows build number does not change.
