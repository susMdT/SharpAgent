using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static HavocImplant.Implant;

namespace HavocImplant.AgentFunctions
{
    public abstract class CommandInterface
    {
        public abstract string Command { get; }
        public abstract bool Dangerous { get; }

        public string Output;
        public Implant Agent;

        public void Init(Implant agent)
        {
            Agent = agent;
        }

        public abstract void Run(string command, int taskId);
        public void ReturnOutput(int taskId)
        {
            Agent.taskingInformation[taskId] = new Implant.task(Agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [{Agent.taskingInformation[taskId].taskCommand}]\n" + Output).Replace("\\", "\\\\").Replace("\"", "\\\""));

        }
    }
}
