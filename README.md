# IoRingReadWritePrimitive
Post exploitation technique to turn arbitrary kernel write / increment into full read/write primitive on Windows 11 22H2+
This PoC is using the HackSysExtremeVulnerableDriver. The PoC supports both arbitrary write and arbitrary increment, controlled through a flag passed into the function from main(). For arbitrary increment, compile the latest HEVD driver from source.

Writeup: https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
