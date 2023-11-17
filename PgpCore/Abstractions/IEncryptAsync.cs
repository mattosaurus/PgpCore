using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptAsync : IDisposable
    {
        Task EncryptFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck, string name);

        Task EncryptStreamAsync(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name);

        Task<string> EncryptArmoredStringAsync(string input, bool withIntegrityCheck, string name);

        Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck);

        Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name);

        Task<string> EncryptArmoredStringAndSignAsync(string input, bool withIntegrityCheck, string name);
    }
}