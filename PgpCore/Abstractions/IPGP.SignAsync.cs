using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface ISignAsync : IDisposable
    {
        Task SignFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor, IDictionary<string, string> headers);

        Task SignStreamAsync(Stream inputStream, Stream outputStream, bool armor, string name, IDictionary<string, string> headers);

        Task<string> SignArmoredStringAsync(string input, string name, IDictionary<string, string> headers);

        Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile, IDictionary<string, string> headers);

        Task ClearSignStreamAsync(Stream inputStream, Stream outputStream, IDictionary<string, string> headers);

        Task<string> ClearSignArmoredStringAsync(string input, IDictionary<string, string> headers);
    }
}
