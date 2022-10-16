using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HavocImplant
{
    public class Config
    {
        static public string[] url = new string[] { "https://192.168.1.106:443/funny_cat.gif", "https://192.168.1.106:443/index.php", "https://192.168.1.106:443/test.txt", "https://192.168.1.106:443/helloworld.js" };
        static public bool secure = false;
        static public int sleepTime = 5000;
        static public int timeout = 15000;
        static public int maxTries = 5;
    }
}
