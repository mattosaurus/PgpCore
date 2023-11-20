using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IDecryptAsync : IDisposable
    {
        Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile);
        Task<Stream> DecryptStreamAsync(Stream inputStream, Stream outputStream);
        Task<string> DecryptArmoredStringAsync(string input);
        Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile);
        Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream);
        Task<string> DecryptArmoredStringAndVerifyAsync(string input);
    }
}
