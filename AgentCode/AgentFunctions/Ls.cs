using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Security.AccessControl;

namespace HavocImplant.AgentFunctions
{
    public class Ls : CommandInterface
    {
        public override string Command => "ls";
        public override bool Dangerous => false;

        private struct Entry
        {
            public string Name;
            public string IsDir;
            public string Length;
            public string LastAccessTime;
            public string LastAccessDate;
            public string Permissions;
        }
        public override async Task Run(int taskId)
        {
            string dir = Agent.taskingInformation[taskId].taskArguments.Replace("\"", "");

            if (dir == "")
            {
                dir = Directory.GetCurrentDirectory();
            }

            if (Directory.Exists(dir)) Output = $"\n Directory of {dir}\n\n";
            else { Output = $"{dir} does not exist!"; ReturnOutput(taskId); }

            try
            {
                DirectorySecurity curDirSecurity = Directory.GetAccessControl(dir);
                Output += $"Permissions: {GetPerm(curDirSecurity)}\n\n";
            }
            catch (UnauthorizedAccessException)
            {
                Output = "We do not have permissions to read that directory!";
                ReturnOutput(taskId);
            }



            List<Entry> entries = new List<Entry>();

            foreach (string directory in Directory.GetDirectories(dir))
            {
                DirectoryInfo dirInfo = new DirectoryInfo(directory);
                string perm = "N/A";
                try
                {
                    DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
                    perm = GetPerm<DirectorySecurity>(dirSecurity);
                }
                catch (UnauthorizedAccessException)  { }

                entries.Add(
                    new Entry()
                    {
                        Name = dirInfo.Name,
                        Length = "",
                        IsDir = "<DIR>",
                        LastAccessDate = dirInfo.LastAccessTime.ToShortDateString(),
                        LastAccessTime = dirInfo.LastAccessTime.ToShortTimeString(),
                        Permissions = perm,
                    }
                );
            }

            foreach (string file in Directory.GetFiles(dir))
            {
                FileInfo fileInfo = new FileInfo(file);
                string perm = "N/A";
                try
                {
                    FileSecurity fileSecurity = fileInfo.GetAccessControl();
                    perm = GetPerm<FileSecurity>(fileSecurity);
                }
                catch
                { 
                }
                entries.Add(
                    new Entry()
                    {
                        Name = fileInfo.Name,
                        Length = fileInfo.Length.ToString(),
                        IsDir = "",
                        LastAccessDate = fileInfo.LastAccessTime.ToShortDateString(),
                        LastAccessTime = fileInfo.LastAccessTime.ToShortTimeString(),
                        Permissions = perm,
                    }
                );
            }

            foreach (Entry entry in entries)
            {
                Output += String.Format("{0,-10}    {1,-8}    {2,-6}    {3,-10}    {4,-40}    {5}\n",
                      entry.LastAccessDate,
                      entry.LastAccessTime,
                      entry.IsDir,
                      entry.Length,
                      entry.Name,
                      entry.Permissions);
            }
            ReturnOutput(taskId);
        }
        public static string GetPerm<T>(T Security) where T : FileSystemSecurity
        {
            string retVal = "";
            foreach (FileSystemAccessRule rule in Security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
            {
                if (rule.AccessControlType == AccessControlType.Allow)
                {
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.FullControl))
                    {
                        return "Full Control";
                    }
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                    {
                        return "Read, Write, Delete, Execute";
                    }
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute))
                    {
                        retVal += "Read, Execute ";
                    }
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.Write))
                    {
                        retVal += "Write ";
                    }
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.ListDirectory))
                    {
                        retVal += "List Contents";
                    }
                }
            }
            return retVal;
        }
    }
}
