using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface ISignSync : IDisposable
    {
        void SignFile(FileInfo inputFile, FileInfo outputFile, bool armor, IDictionary<string, string> headers);

        void SignStream(Stream inputStream, Stream outputStream, bool armor, string name, IDictionary<string, string> headers);

        string SignArmoredString(string input, string name, IDictionary<string, string> headers);

        void ClearSignFile(FileInfo inputFile, FileInfo outputFile, IDictionary<string, string> headers);

        void ClearSignStream(Stream inputStream, Stream outputStream, IDictionary<string, string> headers);

        string ClearSignArmoredString(string input, IDictionary<string, string> headers);
    }
}
