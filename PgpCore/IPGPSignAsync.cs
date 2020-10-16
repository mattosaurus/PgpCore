using System;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore
{
    public interface IPGPSignAsync : IDisposable
    {
        Task SignFileAsync(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys,
            bool armor, bool withIntegrityCheck, string name);
        
        Task SignStreamAsync(Stream inputStream, Stream outputStream,
            Stream privateKeyStream, string passPhrase, bool armor, bool withIntegrityCheck, string name);

        Task SignStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys,
            bool armor, bool withIntegrityCheck, string name);

        Task SignStreamAsync(Stream inputStream, Stream outputStream,
            bool armor, bool withIntegrityCheck, string name);
    }
}