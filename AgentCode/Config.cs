using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HavocImplant
{
    public class Config
    {
        static public string[] url = new string[] { "http://192.168.1.106:80/balls" };
        static public bool secure = false;
        static public int sleepTime = 5000;
        static public int timeout = 15000;
        static public int maxTries = 5;
    }
}
