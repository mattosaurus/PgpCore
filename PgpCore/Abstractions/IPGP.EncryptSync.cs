using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptSync : IDisposable
    {
        void Encrypt(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        void Encrypt(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        string Encrypt(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        void EncryptAndSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        void EncryptAndSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        string EncryptAndSign(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);

        void EncryptFile(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        void EncryptStream(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        string EncryptArmoredString(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        void EncryptStreamAndSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
        string EncryptArmoredStringAndSign(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null);
    }
}
