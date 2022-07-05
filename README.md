# IoRingReadWritePrimitive
Post exploitation technique to turn arbitrary kernel write / increment into full read/write primitive on Windows 11 22H2+
This PoC is using the HackSysExtremeVulnerableDriver. The PoC supports both arbitrary write and arbitrary increment, controlled through a flag passed into the function from main(). For arbitrary increment, compile the latest HEVD driver from source.

Writeup: https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/

This PoC uses an arbitrary overwrite of the RegBuffers field of an I/O ring to point to a fake array of preregistered buffers that can be manipulated by an attacker. The fake buffers can point to kernel addresses, so the attacker can queue read and write operations that generate arbitrary reads and writes.
By using named pipes instead of a file we can avoid leaving any traces for security tools to recognize.
Current implementation reads a page from the NTOS data section and prints it out. This is done using a hard-coded offset so it might break inthe future.
