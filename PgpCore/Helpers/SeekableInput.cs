using System;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Helpers
{
    /// <summary>Owns a seekable scratch stream without allocating memory proportional to input size.</summary>
    internal static class SeekableInput
    {
        internal static FileStream Create()
        {
            string directory = Path.DirectorySeparatorChar == '/' ? PrivateFilePermissions.CreateDirectory(Path.GetTempPath()) : null;
            try { return new OwnedFileStream(directory); }
            catch
            {
                if (directory != null && Directory.Exists(directory)) Directory.Delete(directory);
                throw;
            }
        }

        private sealed class OwnedFileStream : FileStream
        {
            private readonly string _directory;
            internal OwnedFileStream(string directory) : base(
                Path.Combine(directory ?? Path.GetTempPath(), "pgpcore-" + Guid.NewGuid().ToString("N") + ".tmp"),
                FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 16384, FileOptions.DeleteOnClose | FileOptions.Asynchronous)
            {
                _directory = directory;
                try { if (directory != null) PrivateFilePermissions.Restrict(this); }
                catch { Dispose(); throw; }
            }
            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                if (disposing && _directory != null && Directory.Exists(_directory)) Directory.Delete(_directory);
            }
        }

        internal static async Task<FileStream> CopyAsync(Stream source)
        {
            FileStream copy = Create();
            try
            {
                await source.CopyToAsync(copy).ConfigureAwait(false);
                copy.Position = 0;
                return copy;
            }
            catch
            {
                copy.Dispose();
                throw;
            }
        }
    }
}
