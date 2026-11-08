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
