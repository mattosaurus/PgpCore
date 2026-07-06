using System;
using System.Collections.Generic;
using System.IO;

namespace PgpCore.Abstractions
{
    public interface IDetachedSignSync : IDisposable
    {
        void SignDetached(FileInfo inputFile, FileInfo outputFile, bool armor = true, IDictionary<string, string> headers = null);
        void SignDetached(Stream inputStream, Stream outputStream, bool armor = true, IDictionary<string, string> headers = null);
        string SignDetached(string input, IDictionary<string, string> headers = null);

        bool VerifyDetached(FileInfo inputFile, FileInfo signatureFile);
        bool VerifyDetached(Stream inputStream, Stream signatureStream);
        bool VerifyDetached(string input, string signature);
    }
}
