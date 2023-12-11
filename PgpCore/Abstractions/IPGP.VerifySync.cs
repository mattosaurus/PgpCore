using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IVerifySync : IDisposable
    {
        bool Verify(FileInfo inputFile, FileInfo outputFile = null, bool throwIfEncrypted = false);
        bool Verify(Stream inputStream, Stream outputStream = null, bool throwIfEncrypted = false);
        bool Verify(string input, bool throwIfEncrypted = false);
        bool VerifyClear(FileInfo inputFile, FileInfo outputFile = null);
        bool VerifyClear(Stream inputStream, Stream outputStream = null);
        bool VerifyClear(string input, string output = null);

        bool VerifyFile(FileInfo inputFile, bool throwIfEncrypted = false);
        bool VerifyStream(Stream inputStream, bool throwIfEncrypted = false);
        bool VerifyArmoredString(string input, bool throwIfEncrypted = false);
        bool VerifyClearFile(FileInfo inputFile);
        bool VerifyClearStream(Stream inputStream);
        bool VerifyClearArmoredString(string input);
        VerificationResult VerifyAndReadClearFile(FileInfo inputFile);
        VerificationResult VerifyAndReadClearStream(Stream inputStream);
        VerificationResult VerifyAndReadClearArmoredString(string input);
        VerificationResult VerifyAndReadSignedFile(FileInfo inputFile, bool throwIfEncrypted = false);
        VerificationResult VerifyAndReadSignedStream(Stream inputStream, bool throwIfEncrypted = false);
        VerificationResult VerifyAndReadSignedArmoredString(string input, bool throwIfEncrypted = false);
    }
}
