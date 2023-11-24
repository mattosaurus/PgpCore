using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IDecryptAsync : IDisposable
    {
        Task DecryptAsync(FileInfo inputFile, FileInfo outputFile);
        Task DecryptAsync(Stream inputStream, Stream outputStream);
        Task<string> DecryptAsync(string input);
        Task DecryptAndVerifyAsync(FileInfo inputFile, FileInfo outputFile);
        Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream);
        Task<string> DecryptAndVerifyAsync(string input);

        Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile);
        Task DecryptStreamAsync(Stream inputStream, Stream outputStream);
        Task<string> DecryptArmoredStringAsync(string input);
        Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile);
        Task DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream);
        Task<string> DecryptArmoredStringAndVerifyAsync(string input);
    }
}
