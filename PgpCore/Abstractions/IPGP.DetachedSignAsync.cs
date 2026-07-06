using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IDetachedSignAsync : IDisposable
    {
        Task SignDetachedAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, IDictionary<string, string> headers = null);
        Task SignDetachedAsync(Stream inputStream, Stream outputStream, bool armor = true, IDictionary<string, string> headers = null);
        Task<string> SignDetachedAsync(string input, IDictionary<string, string> headers = null);

        Task<bool> VerifyDetachedAsync(FileInfo inputFile, FileInfo signatureFile);
        Task<bool> VerifyDetachedAsync(Stream inputStream, Stream signatureStream);
        Task<bool> VerifyDetachedAsync(string input, string signature);
    }
}
