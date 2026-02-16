#Requires -Version 7.0
<#
.SYNOPSIS
    Binary PE mutation engine for nanahira
    Applies 10 mutations to compiled .sys and .exe files
    Source: https://github.com/Kiy0w0/kernel-mmi

.DESCRIPTION
    After compilation, this script modifies the PE binary structure
    to create a unique fingerprint. Each run produces completely
    different SHA256 hashes without affecting functionality.

    Mutations:
      1. TimeDateStamp      — Randomize compile timestamp
      2. Checksum           — Randomize PE checksum
      3. Rich Header        — Destroy MSVC build fingerprint
      4. Section Names      — Rename PE section names
      5. Debug Directory    — Wipe PDB paths and GUIDs
      6. Linker Version     — Fake linker version numbers
      7. OS Version         — Randomize minimum OS version fields
      8. Polymorphic Junk   — Fill code caves with random bytes
      9. Build GUID         — Stamp unique 128-bit watermark
     10. DOS Stub           — Randomize unused DOS header area
#>

param(
    [Parameter(Mandatory=$true)]
    [string[]]$Files
)

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────
# PE Constants
# ─────────────────────────────────────────────────────────

$IMAGE_DOS_SIGNATURE = 0x5A4D          # "MZ"
$IMAGE_NT_SIGNATURE  = 0x00004550      # "PE\0\0"

# Section name alternatives
$SectionNameMap = @{
    ".text"   = @(".code", ".exec", ".txts", ".main", ".core")
    ".rdata"  = @(".cnst", ".rdat", ".rodt", ".read", ".conf")
    ".data"   = @(".vars", ".heap", ".dats", ".stor", ".memo")
    ".pdata"  = @(".xdta", ".pdta", ".ehdt", ".unwd", ".trap")
    ".rsrc"   = @(".icon", ".rsrc", ".ress", ".rcdt", ".rbin")
    ".reloc"  = @(".fixs", ".rloc", ".base", ".relc", ".patc")
    ".edata"  = @(".expt", ".xprt", ".symb", ".edta", ".func")
    ".idata"  = @(".impt", ".idta", ".deps", ".link", ".refs")
    "INIT"    = @("BOOT", "LOAD", "STRT", "SETUP", "PREP")
    "PAGE"    = @("SWAP", "POOL", "VIRT", "PGBL", "MOVE")
}

# ─────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────

function Read-UInt16([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt16($Data, $Offset)
}

function Read-UInt32([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Write-UInt16([byte[]]$Data, [int]$Offset, [uint16]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Copy($bytes, 0, $Data, $Offset, 2)
}

function Write-UInt32([byte[]]$Data, [int]$Offset, [uint32]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Copy($bytes, 0, $Data, $Offset, 4)
}

function Get-RandomBytes([int]$Count) {
    $buf = [byte[]]::new($Count)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    return $buf
}

function Get-RandomUInt32 {
    $buf = Get-RandomBytes 4
    return [BitConverter]::ToUInt32($buf, 0)
}

function Get-RandomUInt16 {
    $buf = Get-RandomBytes 2
    return [BitConverter]::ToUInt16($buf, 0)
}

# ─────────────────────────────────────────────────────────
# Mutation functions
# ─────────────────────────────────────────────────────────

function Invoke-MutateTimeDateStamp([byte[]]$PE, [int]$NtOffset) {
    # TimeDateStamp is at COFF header + 4 (after Signature)
    $coffOffset = $NtOffset + 4  # after PE\0\0
    $tsOffset = $coffOffset + 4  # TimeDateStamp field
    
    $newTs = Get-RandomUInt32
    Write-UInt32 $PE $tsOffset $newTs
    
    return "TimeDateStamp → 0x{0:X8}" -f $newTs
}

function Invoke-MutateChecksum([byte[]]$PE, [int]$NtOffset) {
    # Checksum is at OptionalHeader + 64 (for PE32+)
    $optOffset = $NtOffset + 24  # OptionalHeader start
    $csOffset = $optOffset + 64  # Checksum field
    
    $newCs = Get-RandomUInt32
    Write-UInt32 $PE $csOffset $newCs
    
    return "Checksum → 0x{0:X8}" -f $newCs
}

function Invoke-MutateRichHeader([byte[]]$PE, [int]$NtOffset) {
    # Rich header is between DOS stub and PE signature
    # Look for "Rich" marker scanning backwards from NT headers
    $richOffset = -1
    for ($i = $NtOffset - 4; $i -ge 0x80; $i--) {
        if ($PE[$i] -eq 0x52 -and $PE[$i+1] -eq 0x69 -and 
            $PE[$i+2] -eq 0x63 -and $PE[$i+3] -eq 0x68) {  # "Rich"
            $richOffset = $i
            break
        }
    }
    
    if ($richOffset -lt 0) {
        return "Rich Header — not found (skipped)"
    }
    
    # Find "DanS" marker for start of rich header
    $dansOffset = -1
    # The XOR key is the DWORD after "Rich"
    $xorKey = Read-UInt32 $PE ($richOffset + 4)
    
    # DanS XORed with key
    $dansXored = 0x536E6144 -bxor $xorKey  # "DanS" 
    for ($i = 0x80; $i -lt $richOffset; $i += 4) {
        if ((Read-UInt32 $PE $i) -eq $dansXored) {
            $dansOffset = $i
            break
        }
    }
    
    if ($dansOffset -lt 0) { $dansOffset = 0x80 }
    
    # Overwrite entire rich header area with random bytes
    $richSize = ($richOffset + 8) - $dansOffset
    $randomBytes = Get-RandomBytes $richSize
    [Array]::Copy($randomBytes, 0, $PE, $dansOffset, $richSize)
    
    return "Rich Header — destroyed ($richSize bytes randomized)"
}

function Invoke-MutateSectionNames([byte[]]$PE, [int]$NtOffset) {
    $coffOffset = $NtOffset + 4
    $numSections = Read-UInt16 $PE ($coffOffset + 2)
    $optHeaderSize = Read-UInt16 $PE ($coffOffset + 16)
    $sectionTableOffset = $NtOffset + 24 + $optHeaderSize
    
    $renamed = 0
    for ($i = 0; $i -lt $numSections; $i++) {
        $secOffset = $sectionTableOffset + ($i * 40)
        
        # Read current name (8 bytes)
        $nameBytes = $PE[$secOffset..($secOffset + 7)]
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
        
        # Check if we have alternatives
        foreach ($key in $SectionNameMap.Keys) {
            if ($name -eq $key) {
                $alts = $SectionNameMap[$key]
                $newName = $alts[(Get-Random -Maximum $alts.Count)]
                
                # Write new name (pad with zeros to 8 bytes)
                $newNameBytes = [System.Text.Encoding]::ASCII.GetBytes($newName)
                # Clear old name
                for ($j = 0; $j -lt 8; $j++) { $PE[$secOffset + $j] = 0 }
                # Write new name
                $copyLen = [Math]::Min($newNameBytes.Length, 8)
                [Array]::Copy($newNameBytes, 0, $PE, $secOffset, $copyLen)
                
                $renamed++
                break
            }
        }
    }
    
    return "Section Names — $renamed sections renamed"
}

function Invoke-MutateDebugDirectory([byte[]]$PE, [int]$NtOffset) {
    # Debug directory RVA is at OptionalHeader + 144 (PE32+, data dir index 6)
    $optOffset = $NtOffset + 24
    $debugDirRva = Read-UInt32 $PE ($optOffset + 144)
    $debugDirSize = Read-UInt32 $PE ($optOffset + 148)
    
    if ($debugDirRva -eq 0 -or $debugDirSize -eq 0) {
        return "Debug Directory — none present (skipped)"
    }
    
    # Convert RVA to file offset using section table
    $coffOffset = $NtOffset + 4
    $numSections = Read-UInt16 $PE ($coffOffset + 2)
    $optHeaderSize = Read-UInt16 $PE ($coffOffset + 16)
    $sectionTableOffset = $NtOffset + 24 + $optHeaderSize
    
    $debugFileOffset = 0
    for ($i = 0; $i -lt $numSections; $i++) {
        $secOffset = $sectionTableOffset + ($i * 40)
        $secVA = Read-UInt32 $PE ($secOffset + 12)
        $secRawSize = Read-UInt32 $PE ($secOffset + 16)
        $secRawPtr = Read-UInt32 $PE ($secOffset + 20)
        
        if ($debugDirRva -ge $secVA -and $debugDirRva -lt ($secVA + $secRawSize)) {
            $debugFileOffset = $secRawPtr + ($debugDirRva - $secVA)
            break
        }
    }
    
    if ($debugFileOffset -eq 0) {
        return "Debug Directory — could not resolve RVA (skipped)"
    }
    
    # Wipe debug directory entries
    $wiped = 0
    for ($off = $debugFileOffset; $off -lt ($debugFileOffset + $debugDirSize); $off += 28) {
        if (($off + 28) -gt $PE.Length) { break }
        
        $debugType = Read-UInt32 $PE ($off + 12)
        $dataSize = Read-UInt32 $PE ($off + 16)
        $dataPtr = Read-UInt32 $PE ($off + 24)  # PointerToRawData
        
        # Wipe the debug data (PDB path, CodeView GUID, etc.)
        if ($dataPtr -gt 0 -and $dataSize -gt 0 -and ($dataPtr + $dataSize) -le $PE.Length) {
            $randomData = Get-RandomBytes $dataSize
            [Array]::Copy($randomData, 0, $PE, $dataPtr, $dataSize)
            $wiped++
        }
    }
    
    # Zero out the debug directory RVA/Size in optional header to hide it
    Write-UInt32 $PE ($optOffset + 144) 0
    Write-UInt32 $PE ($optOffset + 148) 0
    
    return "Debug Directory — $wiped entries wiped"
}

function Invoke-MutateLinkerVersion([byte[]]$PE, [int]$NtOffset) {
    $optOffset = $NtOffset + 24
    
    # MajorLinkerVersion (offset 2), MinorLinkerVersion (offset 3) in OptionalHeader
    $majors = @(14, 15, 16, 17)  # Plausible MSVC linker versions
    $PE[$optOffset + 2] = [byte]($majors[(Get-Random -Maximum $majors.Count)])
    $PE[$optOffset + 3] = [byte](Get-Random -Minimum 10 -Maximum 40)
    
    return "Linker Version → {0}.{1}" -f $PE[$optOffset + 2], $PE[$optOffset + 3]
}

function Invoke-MutateOSVersion([byte[]]$PE, [int]$NtOffset) {
    $optOffset = $NtOffset + 24
    
    # MajorOperatingSystemVersion (offset 40), MinorOperatingSystemVersion (offset 42)
    $osVersions = @(
        @{ Major = 6; Minor = 1 },   # Win7
        @{ Major = 6; Minor = 2 },   # Win8
        @{ Major = 6; Minor = 3 },   # Win8.1
        @{ Major = 10; Minor = 0 }   # Win10/11
    )
    $ver = $osVersions[(Get-Random -Maximum $osVersions.Count)]
    
    Write-UInt16 $PE ($optOffset + 40) ([uint16]$ver.Major)
    Write-UInt16 $PE ($optOffset + 42) ([uint16]$ver.Minor)
    
    # Also MajorSubsystemVersion / MinorSubsystemVersion (offset 48/50)
    Write-UInt16 $PE ($optOffset + 48) ([uint16]$ver.Major)
    Write-UInt16 $PE ($optOffset + 50) ([uint16]$ver.Minor)
    
    return "OS Version → {0}.{1}" -f $ver.Major, $ver.Minor
}

function Invoke-MutatePolymorphicJunk([byte[]]$PE, [int]$NtOffset) {
    # Find code caves (sequences of 0x00 or 0xCC longer than 16 bytes)
    # in executable sections and fill with random but valid-looking bytes
    
    $coffOffset = $NtOffset + 4
    $numSections = Read-UInt16 $PE ($coffOffset + 2)
    $optHeaderSize = Read-UInt16 $PE ($coffOffset + 16)
    $sectionTableOffset = $NtOffset + 24 + $optHeaderSize
    
    $totalFilled = 0
    $IMAGE_SCN_MEM_EXECUTE = 0x20000000
    
    # NOP-like x64 instruction patterns (safe junk that won't crash if somehow executed)
    $nopPatterns = @(
        @(0x90),                         # nop
        @(0x66, 0x90),                   # 2-byte nop
        @(0x0F, 0x1F, 0x00),            # 3-byte nop
        @(0x0F, 0x1F, 0x40, 0x00),      # 4-byte nop
        @(0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00),  # 6-byte nop
        @(0x48, 0x87, 0xC0),            # xchg rax, rax
        @(0x48, 0x89, 0xC0),            # mov rax, rax
        @(0x48, 0x8D, 0x00)             # lea rax, [rax]
    )
    
    for ($i = 0; $i -lt $numSections; $i++) {
        $secOffset = $sectionTableOffset + ($i * 40)
        $secChars = Read-UInt32 $PE ($secOffset + 36)
        $secRawPtr = Read-UInt32 $PE ($secOffset + 20)
        $secRawSize = Read-UInt32 $PE ($secOffset + 16)
        
        # Only modify executable sections
        if (($secChars -band $IMAGE_SCN_MEM_EXECUTE) -eq 0) { continue }
        if ($secRawSize -eq 0) { continue }
        
        # Scan for code caves (>= 32 bytes of 0x00 or 0xCC)
        $caveStart = -1
        $caveMinLen = 32
        
        for ($j = $secRawPtr; $j -lt ($secRawPtr + $secRawSize); $j++) {
            if ($j -ge $PE.Length) { break }
            
            if ($PE[$j] -eq 0x00 -or $PE[$j] -eq 0xCC) {
                if ($caveStart -eq -1) { $caveStart = $j }
            } else {
                if ($caveStart -ne -1) {
                    $caveLen = $j - $caveStart
                    if ($caveLen -ge $caveMinLen) {
                        # Fill cave with random NOP patterns
                        $pos = $caveStart
                        while ($pos -lt $j - 1) {
                            $pattern = $nopPatterns[(Get-Random -Maximum $nopPatterns.Count)]
                            if (($pos + $pattern.Count) -le $j) {
                                for ($k = 0; $k -lt $pattern.Count; $k++) {
                                    $PE[$pos + $k] = $pattern[$k]
                                }
                                $pos += $pattern.Count
                                $totalFilled += $pattern.Count
                            } else {
                                $PE[$pos] = 0x90  # single nop
                                $pos++
                                $totalFilled++
                            }
                        }
                    }
                    $caveStart = -1
                }
            }
        }
    }
    
    return "Polymorphic Junk — $totalFilled bytes filled in code caves"
}

function Invoke-MutateBuildGUID([byte[]]$PE, [int]$NtOffset) {
    # Stamp a unique 128-bit GUID at the end of the last section's raw data
    # This acts as a unique watermark for this build
    
    $coffOffset = $NtOffset + 4
    $numSections = Read-UInt16 $PE ($coffOffset + 2)
    $optHeaderSize = Read-UInt16 $PE ($coffOffset + 16)
    $sectionTableOffset = $NtOffset + 24 + $optHeaderSize
    
    # Find the last section
    $lastSecOffset = $sectionTableOffset + (($numSections - 1) * 40)
    $lastRawPtr = Read-UInt32 $PE ($lastSecOffset + 20)
    $lastRawSize = Read-UInt32 $PE ($lastSecOffset + 16)
    
    # Write GUID at the end of last section (overwrite last 16 bytes of padding)
    $guidOffset = $lastRawPtr + $lastRawSize - 16
    if ($guidOffset -gt 0 -and ($guidOffset + 16) -le $PE.Length) {
        $guid = Get-RandomBytes 16
        [Array]::Copy($guid, 0, $PE, $guidOffset, 16)
        $guidStr = [BitConverter]::ToString($guid).Replace("-","")
        return "Build GUID → $guidStr"
    }
    
    return "Build GUID — could not stamp (section too small)"
}

function Invoke-MutateDOSStub([byte[]]$PE, [int]$NtOffset) {
    # The DOS stub is typically between offset 0x40 and e_lfanew
    # It contains the "This program cannot be run in DOS mode" message
    # We randomize everything between 0x40 and the rich header / PE sig area
    
    $stubStart = 0x40  # After DOS header
    $stubEnd = [Math]::Min($NtOffset, 0x100)  # Don't go past PE sig
    
    # Leave some breathing room
    $stubEnd = [Math]::Max($stubStart + 16, $stubEnd - 16)
    
    if ($stubEnd -le $stubStart) {
        return "DOS Stub — too small to randomize"
    }
    
    $stubSize = $stubEnd - $stubStart
    $randomStub = Get-RandomBytes $stubSize
    [Array]::Copy($randomStub, 0, $PE, $stubStart, $stubSize)
    
    return "DOS Stub — $stubSize bytes randomized"
}

# ─────────────────────────────────────────────────────────
# Main processing
# ─────────────────────────────────────────────────────────

foreach ($filePath in $Files) {
    if (-not (Test-Path $filePath)) {
        Write-Host "  [x] File not found: $filePath" -ForegroundColor Red
        continue
    }
    
    $fileName = Split-Path -Leaf $filePath
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║  Mutating: $($fileName.PadRight(30))║" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
    
    # Read file
    $pe = [System.IO.File]::ReadAllBytes($filePath)
    
    # Validate PE
    $dosSignature = Read-UInt16 $pe 0
    if ($dosSignature -ne $IMAGE_DOS_SIGNATURE) {
        Write-Host "  [x] Not a valid PE file (bad DOS signature)" -ForegroundColor Red
        continue
    }
    
    $ntOffset = Read-UInt32 $pe 0x3C  # e_lfanew
    $ntSignature = Read-UInt32 $pe $ntOffset
    if ($ntSignature -ne $IMAGE_NT_SIGNATURE) {
        Write-Host "  [x] Not a valid PE file (bad NT signature)" -ForegroundColor Red
        continue
    }
    
    # Apply all 10 mutations
    $mutations = @(
        @{ Num = 1;  Name = "TimeDateStamp";    Func = { Invoke-MutateTimeDateStamp $pe $ntOffset } },
        @{ Num = 2;  Name = "Checksum";         Func = { Invoke-MutateChecksum $pe $ntOffset } },
        @{ Num = 3;  Name = "Rich Header";      Func = { Invoke-MutateRichHeader $pe $ntOffset } },
        @{ Num = 4;  Name = "Section Names";    Func = { Invoke-MutateSectionNames $pe $ntOffset } },
        @{ Num = 5;  Name = "Debug Directory";  Func = { Invoke-MutateDebugDirectory $pe $ntOffset } },
        @{ Num = 6;  Name = "Linker Version";   Func = { Invoke-MutateLinkerVersion $pe $ntOffset } },
        @{ Num = 7;  Name = "OS Version";       Func = { Invoke-MutateOSVersion $pe $ntOffset } },
        @{ Num = 8;  Name = "Polymorphic Junk"; Func = { Invoke-MutatePolymorphicJunk $pe $ntOffset } },
        @{ Num = 9;  Name = "Build GUID";       Func = { Invoke-MutateBuildGUID $pe $ntOffset } },
        @{ Num = 10; Name = "DOS Stub";         Func = { Invoke-MutateDOSStub $pe $ntOffset } }
    )
    
    $successCount = 0
    foreach ($mut in $mutations) {
        try {
            $result = & $mut.Func
            Write-Host ("  [{0,2}/10] {1}" -f $mut.Num, $result) -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host ("  [{0,2}/10] {1} — FAILED: {2}" -f $mut.Num, $mut.Name, $_.Exception.Message) -ForegroundColor Red
        }
    }
    
    # Write mutated file back
    [System.IO.File]::WriteAllBytes($filePath, $pe)
    
    # Show new hash
    $hash = (Get-FileHash $filePath -Algorithm SHA256).Hash
    Write-Host ""
    Write-Host "  [+] $successCount/10 mutations applied" -ForegroundColor Green
    Write-Host "  [#] SHA256: $hash" -ForegroundColor Cyan
    Write-Host ""
}
