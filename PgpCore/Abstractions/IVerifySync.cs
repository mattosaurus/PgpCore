using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IVerifyAsync : IDisposable
    {
        Task<bool> VerifyFileAsync(FileInfo inputFile, bool throwIfEncrypted);
        Task<bool> VerifyStreamAsync(Stream inputStream, bool throwIfEncrypted);
        Task<bool> VerifyArmoredStringAsync(string input);
        Task<bool> VerifyClearFileAsync(FileInfo inputFile);
        Task<bool> VerifyClearStreamAsync(Stream inputStream);
        Task<bool> VerifyClearArmoredStringAsync(string input);
        Task<VerificationResult> VerifyAndReadClearFileAsync(FileInfo inputFile);
        Task<VerificationResult> VerifyAndReadClearStreamAsync(Stream inputStream);
        Task<VerificationResult> VerifyAndReadClearArmoredStringAsync(string input);
        Task<VerificationResult> VerifyAndReadSignedFileAsync(FileInfo inputFile, bool throwIfEncrypted);
        Task<VerificationResult> VerifyAndReadSignedStreamAsync(Stream inputStream, bool throwIfEncrypted);
        Task<VerificationResult> VerifyAndReadSignedArmoredStringAsync(string input, bool throwIfEncrypted);
    }
}
