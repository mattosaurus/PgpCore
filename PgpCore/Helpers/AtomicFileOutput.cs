using System;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Helpers
{
    /// <summary>Stages file output beside its destination and commits only completed operations.</summary>
    internal sealed class AtomicFileOutput : IDisposable
    {
        private readonly string _destination;
        private readonly string _staging;
        private readonly string _privateDirectory;
        private FileStream _stream;

        internal AtomicFileOutput(FileInfo destination)
        {
            _destination = destination.FullName;
            if (Path.DirectorySeparatorChar == '/')
                _privateDirectory = PrivateFilePermissions.CreateDirectory(destination.DirectoryName);
            _staging = Path.Combine(_privateDirectory ?? destination.DirectoryName, ".pgpcore-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                _stream = new FileStream(_staging, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                if (_privateDirectory != null) PrivateFilePermissions.Restrict(_stream);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal Stream Stream => new NonClosingStream(_stream);

        internal void Commit(string backup = null)
        {
            _stream.Flush(true);
            _stream.Dispose();
            _stream = null;
            if (File.Exists(_destination))
                File.Replace(_staging, _destination, backup);
            else
                File.Move(_staging, _destination);
        }

        public void Dispose()
        {
            _stream?.Dispose();
            if (File.Exists(_staging))
                File.Delete(_staging);
            if (_privateDirectory != null && Directory.Exists(_privateDirectory))
                Directory.Delete(_privateDirectory);
        }

        internal static async Task WriteAsync(FileInfo destination, Func<Stream, Task> write)
        {
            using (var output = new AtomicFileOutput(destination))
            {
                await write(output.Stream).ConfigureAwait(false);
                output.Commit();
            }
        }

        internal static async Task<bool> VerifyAsync(FileInfo destination, Func<Stream, Task<bool>> verify)
        {
            using (var output = new AtomicFileOutput(destination))
            {
                bool verified = await verify(output.Stream).ConfigureAwait(false);
                if (verified)
                    output.Commit();
                return verified;
            }
        }

        /// <summary>
        /// Generates a complete key pair before changing either destination. If the second commit
        /// fails, restores the first destination; a failed restoration retains its recovery backup.
        /// Two separate files cannot provide a crash-atomic transaction.
        /// </summary>
        internal static void WriteKeyPair(FileInfo publicFile, FileInfo privateFile, Action<Stream, Stream> write)
        {
            StringComparison comparison = Path.DirectorySeparatorChar == '\\'
                ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (string.Equals(publicFile.FullName, privateFile.FullName, comparison))
                throw new ArgumentException("Public and private key destinations must be different files.");

            using (var publicOutput = new AtomicFileOutput(publicFile))
            using (var privateOutput = new AtomicFileOutput(privateFile))
            {
                write(publicOutput.Stream, privateOutput.Stream);
                string backup = Path.Combine(publicFile.DirectoryName, ".pgpcore-" + Guid.NewGuid().ToString("N") + ".bak");
                bool publicExisted = File.Exists(publicFile.FullName);
                publicOutput.Commit(publicExisted ? backup : null);
                try
                {
                    privateOutput.Commit();
                }
                catch (Exception commitError)
                {
                    try
                    {
                        if (publicExisted)
                            File.Replace(backup, publicFile.FullName, null);
                        else
                            File.Delete(publicFile.FullName);
                    }
                    catch (Exception restoreError)
                    {
                        throw new IOException("Key pair commit and restoration failed. Recovery backup: " + backup,
                            new AggregateException(commitError, restoreError));
                    }
                    throw;
                }
                if (File.Exists(backup))
                    File.Delete(backup);
            }
        }
    }
}
