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
        {
            if (FChmod(stream.SafeFileHandle.DangerousGetHandle().ToInt32(), 0x180) != 0)
                throw new IOException("Unable to restrict staging file permissions (errno " + Marshal.GetLastWin32Error() + ").");
        }

        [DllImport("libc", EntryPoint = "mkdir", SetLastError = true)]
        private static extern int Mkdir(string path, uint mode);
        [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
        private static extern int FChmod(int descriptor, uint mode);
    }
}
