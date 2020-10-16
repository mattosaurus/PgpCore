using System;
using System.IO;

namespace PgpCore
{
    public interface IPGPSign : IDisposable
    {
        void SignFile(string inputFilePath, string outputFilePath,
            string privateKeyFilePath, string passPhrase, bool armor, bool withIntegrityCheck, string name);

        void SignFile(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys,
            bool armor, bool withIntegrityCheck, string name);

        void SignStream(Stream inputStream, Stream outputStream,
            Stream privateKeyStream, string passPhrase, bool armor, bool withIntegrityCheck, string name);

        void SignStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys,
            bool armor, bool withIntegrityCheck, string name);

        void SignStream(Stream inputStream, Stream outputStream,
            bool armor, bool withIntegrityCheck, string name);
    }
}