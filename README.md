# KaBan Crackme: Locating the Target Message and Verifying the "Packer" Hypothesis

## Sample Identification & Metadata
* **Challenge:** KaBan crackme ("Reverse this, find where this message is printed")
* **Original File Name:** `0LLRi9C10LHQuCDQvNC10L3Rjw.exe`
* **File Type:** PE32+ executable (Console) x86-64, Microsoft Visual C++ runtime
* **MD5:** `63809c874f7ca1de998cecf519a5fe95`
* **SHA-256:** `269f66eb409a8076e60f9cf7402b6d5dba94a33331d19bd2cd49da220a769e53`
* **File Size:** 269,312 bytes
* **Solver:** DeepDominance
* **Archive Password:** `infected` (`malware_sample.7z` holds the original file, the Scylla dump and the patched dump)

> **Revision (2026-11-06).** The first version of this write-up described the sample as packed by a custom protector and treated an `IsDebuggerPresent` block as anti-debugging. A static re-check (section 6) showed that the file is **not packed** and that the block belongs to the MSVC C runtime. The dynamic workflow is kept below because it is a correct unpacking procedure, but its conclusions are corrected.

---

## Executive Summary
The goal of the crackme is to find where the message `"Reverse this shit, find where this message is printed."` is printed. The message is referenced directly in `main` (`lea rdx, [rip+0x35c6c]` at `0x140001464`, followed by the print call at `0x14000146b`), so the challenge can be solved statically in the original file.

A dynamic "unpacking" pass (x64dbg, `VirtualProtect` breakpoints, Scylla dump and IAT rebuild) was performed first. Comparing the dump with the original file afterwards showed that the `.text` section is byte-for-byte identical: no code is decrypted or unpacked at run time.

---

## Binary Technical Specifications
* **Sections:** `.text` (entropy 6.45), `.rdata`, `.data`, `.pdata`, `.fptable`, `_RDATA`, `.reloc`: a standard MSVC layout
* **Imports:** `KERNEL32.dll`, 80 functions (complete import table, not a packer stub)
* **Entry point:** RVA `0xCF80` (`mainCRTStartup`)
* **Toolchain:** PE-bear, x64dbg, Scylla x64 v0.9.8, IDA Pro / IDA Free; verification with Python (`pefile`, Capstone)

---

## Technical Walkthrough

### 1. Static Triage
PE-bear shows a normal MSVC section table and a complete import table (80 `KERNEL32.dll` functions, including `VirtualProtect`, `LoadLibraryExW` and `GetProcAddress`, which are regular imports of the MSVC runtime). The target message is present in `.rdata` as plain text.

![PE-bear Initial Analysis](images/1.png)
![PE-bear Initial Analysis](images/2.png)
![PE-bear Initial Analysis](images/3.png)

### 2. Dynamic Tracing (x64dbg)
The sample was traced in x64dbg with a breakpoint on `kernel32.VirtualProtect`. Execution was followed back to the main module, and the address `0x00007FF7DE478289` (RVA `0x18289`) was recorded as the "OEP".

**Correction:** RVA `0x18289` is not the entry point. It is a return address inside a CRT initialization routine (the instruction after `call 0x140019418` in the function starting at RVA `0x18280`). The real entry point is RVA `0xCF80`, taken from the PE header; it is the same in the original file and in memory.

![x64dbg Trace](images/4.png)

### 3. Memory Dump and IAT Reconstruction (Scylla)
Scylla x64 was attached to the running process. It found the IAT at `0x00007FF7DE49AF08` (size `0x280`), resolved 80/80 imports and wrote the dump `unpacked_SCY.exe` with an additional `.SCY` section.

![Scylla IAT Reconstruction](images/5.jfif)
![PE-bear Re-alignment Verification](images/6.png)

### 4. The `IsDebuggerPresent` Block
The dump was patched at three conditional jumps after `IsDebuggerPresent` (RVA `0x17DF4`, `0x17DF8`, `0x17DFD`; `75 10`, `75 0C`, `74 07` replaced with `90 90`).

**Correction:** this block is the MSVC runtime function `__scrt_fastfail`: `RtlLookupFunctionEntry` → `RtlVirtualUnwind` → `IsDebuggerPresent` → `SetUnhandledExceptionFilter(NULL)` → `UnhandledExceptionFilter`. It runs only when the program fails fast (for example, on stack corruption) and hands control to an attached debugger. It is not an anti-debugging check, and the patches do not change the program's normal behaviour.

![IDA Pro Patch](images/7.png)
![IDA Pro Patch](images/8.png)

### 5. Core Logic
`main` loads the target string with `lea rdx, aReverseThisShi` and passes it to the `std::cout` wrapper (`sub_7FF7DE461530` in the dump, `0x140001530` in the original file). There are no password checks or hidden flag routines.

![IDA Pro Core Logic Graph View](images/9.png)

### 6. Verification: Is the File Packed?
The original file and the Scylla dump were compared section by section (`section_cmp.py`, `pefile`):

```
ImageBase file 0x140000000, dump 0x7ff7de460000
section     bytes  differ
.text      160834       0
.rdata      87676    4626
.data        5120     305
.pdata       8712       0
.fptable      256       8
_RDATA       1092       0
.reloc       2296       0
sections only in the dump: .SCY
```

* `.text` is identical, so no code was decrypted or unpacked at run time.
* The differences in `.rdata` and `.data` come from base relocations (the image was loaded at `0x7ff7de460000` instead of `0x140000000`) and from the import address table filled in by the loader.
* The target string and the `lea rdx` that references it are visible in the original file.

**Lesson:** before running an unpacking procedure, check the packing hypothesis statically: section names and entropy, the size of the import table, and finally a file-versus-dump comparison of the code section.

---

## Detection Signature (YARA)
Tested on the original file and the dump (both match) and on 720 unrelated PE/ELF files (no matches). The previous rule also matched unrelated binaries through its `$s2 and $hex_pattern` branch (`KERNEL32.dll` plus a generic `lea/call/nop` pattern), so it was replaced.

```yara
rule KaBan_Crackme_Target
{
    meta:
        description = "KaBan crackme: target message and the code that prints it"
        author      = "DeepDominance"
        date        = "2026-11-06"
        sample_sha256 = "269f66eb409a8076e60f9cf7402b6d5dba94a33331d19bd2cd49da220a769e53"
        note        = "matches the original file and the Scylla dump alike: the sample is not packed"

    strings:
        $msg  = "Reverse this shit, find where this message is printed." ascii
        // lea rdx, [rip+0x35c6c] ; call 0x140001530 ; nop  (the print call in main)
        $code = { 48 8D 15 6C 5C 03 00 E8 C0 00 00 00 90 }

    condition:
        uint16(0) == 0x5A4D and $msg and $code
}
```

### Note
This write-up is for educational purposes. The analysis was carried out in an isolated virtual machine.
