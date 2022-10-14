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
        public static void Run(Implant agent, string time)
        {
            Console.WriteLine($"Received sleep request of {time}");
            if (Int32.TryParse(time, out int timeInt))
            {
                agent.sleepTime = timeInt * 1000;
                agent.outputData += $"[+] Implant sleep time set to {timeInt}!";
            }
            else agent.outputData += $"[!] Implant sleep time was not valid!";
        }
    }
}
