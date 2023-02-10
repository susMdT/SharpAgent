using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    public class Sleep : CommandInterface
    {
        public override string Command => "sleep";
        public override bool Dangerous => false;
        public override async Task Run(int taskId)
        {
            Output = "";
            if (Int32.TryParse(Agent.taskingInformation[taskId].taskArguments, out int timeInt))
            {
                Agent.sleepTime = timeInt * 1000;
                Output = $"Implant sleep time set to {timeInt}!\n";
            }
            else 
            {
                Output = "Implant sleep time was not valid!\n\"";
            }
            ReturnOutput(taskId);
        }
    }
}
