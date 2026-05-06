using System;
using System.Runtime.InteropServices;

namespace GIDR.Core
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

        // TCP Table constants
        public const int AF_INET = 2;  // IPv4
        public const int AF_INET6 = 23; // IPv6
        public const int TCP_TABLE_OWNER_PID_ALL = 5;

        // MIB_TCP_STATE enum values
        public const int MIB_TCP_STATE_ESTABLISHED = 5;

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

        // TCP connection structures for GetExtendedTcpTable
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            // Followed by array of MIB_TCPROW_OWNER_PID
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public uint dwState;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6TABLE_OWNER_PID
        {
            public uint dwNumEntries;
            // Followed by array of MIB_TCP6ROW_OWNER_PID
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

        // GetExtendedTcpTable for reliable network connection enumeration
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref uint pdwSize,
            bool bOrder,
            uint ulAf,
            uint TableClass,
            uint Reserved);

        // Helper to convert network byte order port to host byte order
        public static ushort ntohs(ushort netshort)
        {
            return (ushort)((netshort >> 8) | (netshort << 8));
        }

        // Helper to convert IPv4 address from network to string
        public static string ConvertIPv4Address(uint addr)
        {
            return string.Format("{0}.{1}.{2}.{3}",
                (addr >> 0) & 0xFF,
                (addr >> 8) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 24) & 0xFF);
        }

        // Helper to convert IPv6 address bytes to string
        public static string ConvertIPv6Address(byte[] addr)
        {
            if (addr == null || addr.Length != 16) return "::";
            var groups = new string[8];
            for (int i = 0; i < 8; i++)
            {
                groups[i] = string.Format("{0:x2}{1:x2}", addr[i * 2], addr[i * 2 + 1]);
            }
            return string.Join(":", groups);
        }

        public static string GetTcpStateString(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTENING";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECEIVED";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN";
            }
        }

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
