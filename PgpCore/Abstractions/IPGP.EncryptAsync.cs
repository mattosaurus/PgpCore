using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptAsync : IDisposable
    {
        Task EncryptFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck, IDictionary<string, string> headers);

        Task EncryptStreamAsync(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name, IDictionary<string, string> headers);

        Task<string> EncryptArmoredStringAsync(string input, bool withIntegrityCheck, string name, IDictionary<string, string> headers);

        Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck, IDictionary<string, string> headers);

        Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name, IDictionary<string, string> headers);

        Task<string> EncryptArmoredStringAndSignAsync(string input, bool withIntegrityCheck, string name, IDictionary<string, string> headers);
    }
}