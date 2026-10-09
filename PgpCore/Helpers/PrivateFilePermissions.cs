using System;
using System.IO;
using System.Runtime.InteropServices;

namespace PgpCore.Helpers
{
    internal static class PrivateFilePermissions
    {
        internal static string CreateDirectory(string parent)
        {
            string path = Path.Combine(parent, ".pgpcore-" + Guid.NewGuid().ToString("N"));
            // Create the containing directory privately from its first instant, before writing secrets.
            if (Mkdir(path, 0x1C0) != 0)
                throw new IOException("Unable to create private staging directory (errno " + Marshal.GetLastWin32Error() + ").");
            return path;
        }

        internal static void Restrict(FileStream stream)
            => SetMode(stream, 0x180);

        internal static void SetMode(FileStream stream, int mode)
        {
            if (FChmod(stream.SafeFileHandle.DangerousGetHandle().ToInt32(), (uint)mode) != 0)
                throw new IOException("Unable to set staging file permissions (errno " + Marshal.GetLastWin32Error() + ").");
        }

        internal static int? ReadMode(string path)
        {
            if (Stat(path, out FileStatus status) == 0)
                return status.Mode & 0x1FF;
            int error = Marshal.GetLastWin32Error();
            if (error == 2) return null; // ENOENT: a new output keeps its creation/umask defaults.
            throw new IOException("Unable to read destination permissions (errno " + error + ").");
        }

        // The .NET runtime's portable stat layout avoids platform-specific libc struct stat layouts.
        // It is part of the runtime already used for Unix FileStream operations.
        [StructLayout(LayoutKind.Sequential)]
        private struct FileStatus
        {
            internal int Flags, Mode;
            internal uint Uid, Gid;
            internal long Size, ATime, ATimeNsec, MTime, MTimeNsec, CTime, CTimeNsec;
            internal long BirthTime, BirthTimeNsec, Dev, RDev, Ino;
            internal uint UserFlags;
        }

        [DllImport("System.Native", EntryPoint = "SystemNative_Stat", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern int Stat(string path, out FileStatus status);

        [DllImport("libc", EntryPoint = "mkdir", SetLastError = true)]
        private static extern int Mkdir(string path, uint mode);
        [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
        private static extern int FChmod(int descriptor, uint mode);
    }
}
