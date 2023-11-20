using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptSync : IDisposable
    {
        void EncryptFile(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck, IDictionary<string, string> headers);

        void EncryptStream(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name, IDictionary<string, string> headers);

        string EncryptArmoredString(string input, bool withIntegrityCheck, string name, IDictionary<string, string> headers);

        void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, bool armor, bool withIntegrityCheck, IDictionary<string, string> headers);

        void EncryptStreamAndSign(Stream inputStream, Stream outputStream, bool armor, bool withIntegrityCheck, string name, IDictionary<string, string> headers);

        string EncryptArmoredStringAndSign(string input, bool withIntegrityCheck, string name, IDictionary<string, string> headers);
    }
}
