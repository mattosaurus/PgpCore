using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptSync : IDisposable
    {
        void Encrypt(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void Encrypt(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string Encrypt(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptAndSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptAndSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string EncryptAndSign(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);

        void EncryptFile(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptStream(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string EncryptArmoredString(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptStreamAndSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string EncryptArmoredStringAndSign(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
    }
}
