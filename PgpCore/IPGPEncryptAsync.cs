using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore
{
    public interface IPGPEncryptAsync : IDisposable
    {
        Task EncryptFileAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, 
            bool armor, bool withIntegrityCheck, string name);
        
        Task EncryptStreamAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream, 
            bool armor, bool withIntegrityCheck, string name);

        Task EncryptStreamAsync(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams, 
            bool armor, bool withIntegrityCheck, string name);

        Task EncryptStreamAsync(Stream inputStream, Stream outputStream,
            bool armor, bool withIntegrityCheck, string name);
    }
}