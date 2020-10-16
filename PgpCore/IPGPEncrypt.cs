using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore
{
    public interface IPGPEncrypt : IDisposable
    {
        void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyFilePath, bool armor, bool withIntegrityCheck, string name);

        void EncryptFile(string inputFilePath, string outputFilePath, IEnumerable<string> publicKeyFilePaths, bool armor, bool withIntegrityCheck, string name);

        void EncryptStream(Stream inputStream, Stream outputStream, Stream publicKeyStream, bool armor, bool withIntegrityCheck, string name);

        void EncryptStream(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams, bool armor, bool withIntegrityCheck, string name);

        void EncryptStream(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name);
    }
}