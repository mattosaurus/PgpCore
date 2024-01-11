using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface ISignSync : IDisposable
    {
        void Sign(FileInfo inputFile, FileInfo outputFile, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void Sign(Stream inputStream, Stream outputStream, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string Sign(string input, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void ClearSign(FileInfo inputFile, FileInfo outputFile, IDictionary<string, string> headers = null);
        void ClearSign(Stream inputStream, Stream outputStream, IDictionary<string, string> headers = null);
        string ClearSign(string input, IDictionary<string, string> headers = null);

        void SignFile(FileInfo inputFile, FileInfo outputFile, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void SignStream(Stream inputStream, Stream outputStream, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string SignArmoredString(string input, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void ClearSignFile(FileInfo inputFile, FileInfo outputFile, IDictionary<string, string> headers = null);
        void ClearSignStream(Stream inputStream, Stream outputStream, IDictionary<string, string> headers = null);
        string ClearSignArmoredString(string input, IDictionary<string, string> headers = null);
    }
}
