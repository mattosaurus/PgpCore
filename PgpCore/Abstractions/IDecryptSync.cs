using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IDecryptSync : IDisposable
    {
        void DecryptFile(FileInfo inputFile, FileInfo outputFile);
        Stream DecryptStream(Stream inputStream, Stream outputStream);
        string DecryptArmoredString(string input);
        void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile);
        Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream);
        string DecryptArmoredStringAndVerify(string input);
    }
}
