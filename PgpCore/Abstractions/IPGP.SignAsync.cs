using System;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface ISignAsync : IDisposable
    {
        Task SignFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor);

        Task SignStreamAsync(Stream inputStream, Stream outputStream, bool armor, string name);

        Task<string> SignArmoredStringAsync(string input, string name);

        Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile);

        Task ClearSignStreamAsync(Stream inputStream, Stream outputStream);

        Task<string> ClearSignArmoredStringAsync(string input);
    }
}
