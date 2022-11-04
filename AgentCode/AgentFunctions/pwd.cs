using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    class pwd
    {
        public static void Pwd(Implant agent, int taskId)
        {
            string currentdir = AppDomain.CurrentDomain.BaseDirectory;
            agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\n" + currentdir).Replace("\\", "\\\\").Replace("\"", "\\\""));

        }
    }
}
