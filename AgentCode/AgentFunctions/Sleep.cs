using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    public class Sleep
    {
        public static void Run(Implant agent, string time, int taskId)
        {
            Console.WriteLine($"Received sleep request of {time}");
            if (Int32.TryParse(time, out int timeInt))
            {
                agent.sleepTime = timeInt * 1000;
                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, $"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\nImplant sleep time set to {timeInt}!\n".Replace("\\", "\\\\"));
            }
            else agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, $"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\nImplant sleep time was not valid!\n".Replace("\\", "\\\\"));
        }
    }
}
