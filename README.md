# SharpAgent
C# havoc implant

A .NET Framework test agent for Havoc C2. I just wanna learn how to make c2 implants. Will receive updates for now.  
Just modify the handler to your teamserver. Also it's probably really buggy right now.

Supports http/s, but can only call back to one host address  
Arguments with multiple spaces are buggy right now

## Commands 
| Command      | Description | Example |
| ----------- | ----------- | ----------- |
| exit   | Tasks the implant to exit|  exit |
| ls   | List directories| ls \program files  |
| shell      | Run a command via cmd.exe /c| shell net localgroup "Printer Operators"|
| upload   | Upload a file        |   upload /etc/passwd \windows\temp\bruh.txt|
| download   | Download a file        | download \windows\temp\bruh.txt|
| bofexec*   | Run a beacon object file in memory      |  bofexec /opt/whoami.x64.o |
| inline_assembly   | Run a .NET assembly in memory        |  inline_assembly /opt/Seatbelt.exe |
| inline_pe   | Run a PE in memory        |  inline_pe /opt/mimikatz.exe |

bofexec is incredbibly funky right now and baically experiemental. When client can take multiple args (unless its a skill issue from me) then arg support will be resolved.

## Some OPSEC BS
idk shit so this is my guess of the situation based on my code
* 4 NTAPIs are stuck within the RWX JIT space (where the sacrifical Gate* methods are).
* No obfuscation, assembly name is "HavocImplant", and strings are used instead of hashes for invoking ntapi
* inline_pe clears the PE header, but after execution, doesn't seem to clear the managed byte array of the PE. I think the unmanaged one used for execution is cleaned up successfully though. Also leaves conhost.exe (hidden) cause I can't figure out how to close it properly. 
* bofexec currently has the bof objectfile in the resource section. However, it could be downloaded into memory instead.
* inline assembly creates a sacrificial appdomain to load assembly.
* shell spawns cmd

## Credits
RastaMouse - SharpC2 Drone command interface/handling, filesystem listing
codex_tf2 - PyHmmm + documentation on comm structure
thiagomayllart - DarkMelkor for inline assembly
Nettitude - Bofexec and Inline PE base
Octoberfest7 - Capturing Inline PE output with Windows Application
ChatGPT - String formatting, manual deserialization, json stuff

