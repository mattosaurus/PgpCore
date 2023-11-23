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
