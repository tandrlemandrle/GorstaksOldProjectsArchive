using System;
using System.Runtime.InteropServices;

namespace GEdr.Core
{
    public static class NativeMethods
    {
        public const int PROCESS_VM_READ = 0x0010;
        public const int PROCESS_QUERY_LIMITED = 0x1000;
        public const uint MEM_COMMIT = 0x1000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint MEM_IMAGE = 0x1000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress,
            byte[] buffer, int size, out int bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr address,
            out MEMORY_BASIC_INFORMATION buffer, int length);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        public static bool ContainsBytes(byte[] haystack, int haystackLen, byte[] needle)
        {
            if (needle.Length > haystackLen) return false;
            int limit = haystackLen - needle.Length;
            for (int i = 0; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }
    }
}
