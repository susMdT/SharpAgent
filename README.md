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

bofexec is incredbibly funky right now

