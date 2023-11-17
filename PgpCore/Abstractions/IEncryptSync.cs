using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptSync : IDisposable
    {
        void EncryptFile(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck, string name);

        void EncryptStream(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name);

        string EncryptArmoredString(string input, bool withIntegrityCheck, string name);

        void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck);

        void EncryptStreamAndSign(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name);

        string EncryptArmoredStringAndSign(string input, bool withIntegrityCheck, string name);
    }
}
