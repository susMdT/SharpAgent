# SharpAgent
C# havoc implant

A .NET Framework test agent for Havoc C2. I just wanna learn how to make c2 implants. Will receive updates for now.  
Just modify the handler to your teamserver. Also it's probably really buggy right now.

Supports http/s, but can only call back to one host address

## Commands 
| Command      | Description | Example |
| ----------- | ----------- | ----------- |
| exit   | Tasks the implant to exit|  exit |
| ls   | List directories| ls \program files  |
| shell      | Run a command via cmd.exe /c| shell net localgroup "Printer Operators"|
| sleep   | Change the sleep time        |  sleep 5|
|pwd | Get Current Directory | pwd|
|upload | upload a file to remote host | upload /home/test.txt test.txt|
