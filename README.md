# Celeborn

Celeborn is a Userland API Unhooker that I developed for learning Windows APIs and Syscall implementations. It mainly detects and patches hooking instructions in NTDLL.dll file. All PRs are welcome!


# How It Works?

Celeborn takes the hooked NTDLL.dll module from the in-memory module list that exists in PEB structure (specifically, LoaderData member), parses its export directory to detect hooked functions. To do that, it traverses all Nt related functions, and check their first four bytes. If they are not `0x4C,0x8B,0xD1,0xB8`, the tool itself qualifies them as hooked and started to patch them.

To get a fresh and unhooked NTDLL.dll file, Celeborn loads the file as a section and maps as an image. While patching a function, it copies the first 24 bytes of the clear function address (after parsing the export directory again), and overwrites the hooked one.

Before unhooking the functions, I defined predefined syscalls in the assembly format because I realized that functions that are used for unhooking process might be also hooked. During patching and detecting, Celeborn is using these predefined arbitrary syscall functions.

# TO-DO List
- Generic Predefined Syscall Numbers
- More silent techniques (especially for newly created section)
- Refactor

# References

I used different techniques from the following tools for both silence and learning.

- https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
- https://github.com/Mr-Un1k0d3r/EDRs
- https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/
- https://github.com/am0nsec/HellsGate
