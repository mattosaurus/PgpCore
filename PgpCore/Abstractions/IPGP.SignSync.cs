using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface ISignSync : IDisposable
    {
        void SignFile(FileInfo inputFile, FileInfo outputFile, bool armor);

        void SignStream(Stream inputStream, Stream outputStream, bool armor, string name);

        string SignArmoredString(string input, string name);

        void ClearSignFile(FileInfo inputFile, FileInfo outputFile);

        void ClearSignStream(Stream inputStream, Stream outputStream);

        string ClearSignArmoredString(string input);
    }
}
