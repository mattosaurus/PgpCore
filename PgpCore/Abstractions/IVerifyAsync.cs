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
        bool VerifyFile(FileInfo inputFile, bool throwIfEncrypted);
        bool VerifyStream(Stream inputStream, bool throwIfEncrypted);
        bool VerifyArmoredString(string input);
        bool VerifyClearFile(FileInfo inputFile);
        bool VerifyClearStream(Stream inputStream);
        bool VerifyClearArmoredString(string input);
        VerificationResult VerifyAndReadClearFile(FileInfo inputFile);
        VerificationResult VerifyAndReadClearStream(Stream inputStream);
        VerificationResult VerifyAndReadClearArmoredString(string input);
        VerificationResult VerifyAndReadSignedFile(FileInfo inputFile, bool throwIfEncrypted);
        VerificationResult VerifyAndReadSignedStream(Stream inputStream, bool throwIfEncrypted);
        VerificationResult VerifyAndReadSignedArmoredString(string input, bool throwIfEncrypted);
    }
}
