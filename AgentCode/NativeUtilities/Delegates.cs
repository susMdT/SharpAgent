using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
namespace HavocImplant.NativeUtils
{
    public class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void NtCreateThreadEx(
            ref IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref UInt32 NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref Structs.UNICODE_STRING destinationString, 
            [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenFile(
            ref IntPtr FileHandle,
            Structs.Win32.Enums.FileAccessFlags DesiredAccess,
            ref Structs.OBJECT_ATTRIBUTES ObjAttr,
            ref Structs.IO_STATUS_BLOCK IoStatusBlock,
            Structs.Win32.Enums.FileShareFlags ShareAccess,
            Structs.Win32.Enums.FileOpenFlags OpenOptions);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtFreeVirtualMemory(
            IntPtr ProcessHandle, 
            ref IntPtr BaseAddress, 
            ref IntPtr RegionSize,
            UInt32 FreeType);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LoadLibraryA(
            string file
            );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int MessageBox(
            IntPtr hWnd,
            string lptext,
            string lpcation,
            uint type);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWaitForSingleObject(
            IntPtr Handle,
            bool Alertable,
            IntPtr Timeout);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(
            IntPtr hThread,
            UInt32 milliseconds );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtTerminateProcess(
            IntPtr ProcessHandle,
            uint ExitStatus);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtTerminateThread(
            IntPtr ThreadHandle,
            uint ExitStatus);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCurrentThread();
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            IntPtr returnLength);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GenericPtr();
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool GetExitCodeThread(IntPtr hThread, out int lpExitcode);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void ZeroMemory(IntPtr dest, int size);
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCommandLineA();
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreatePipe(
            out IntPtr hReadPipe, 
            out IntPtr hWritePipe, 
            ref Structs.Win32.SECURITY_ATTRIBUTES lpPipeAttributes, 
            uint nSize
            );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SetStdHandle(
            int nStdHandle, 
            IntPtr hHandle);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadFile(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseHandle(IntPtr hObject);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool AllocConsole();
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetConsoleWindow();
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DestroyWindow(IntPtr hWnd);

    }
}
