using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Models;
using System.IO;

namespace PgpCore
{
    public partial class PGP : IVerifySync
    {
        #region Verify

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Throw if inputFile contains encrypted data. Otherwise, verify encryption key.</param>
        public bool Verify(FileInfo inputFile, FileInfo outputFile = null, bool throwIfEncrypted = false) => VerifyAsync(inputFile, outputFile, throwIfEncrypted).GetAwaiter().GetResult();

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="outputStream">Stream to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public bool Verify(Stream inputStream, Stream outputStream = null, bool throwIfEncrypted = false) => VerifyAsync(inputStream, outputStream, throwIfEncrypted).GetAwaiter().GetResult();

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public bool Verify(string input, bool throwIfEncrypted = false) => VerifyAsync(input, throwIfEncrypted).GetAwaiter().GetResult();

        public bool VerifyFile(FileInfo inputFile, bool throwIfEncrypted = false) => Verify(inputFile, null, throwIfEncrypted);

        public bool VerifyStream(Stream inputStream, bool throwIfEncrypted = false) => Verify(inputStream, null, throwIfEncrypted);

        public bool VerifyArmoredString(string input, bool throwIfEncrypted = false) => Verify(input, throwIfEncrypted);

        public VerificationResult VerifyAndReadSignedFile(FileInfo inputFile, bool throwIfEncrypted = false) => VerifyAndReadSignedFileAsync(inputFile, throwIfEncrypted).GetAwaiter().GetResult();

        public VerificationResult VerifyAndReadSignedStream(Stream inputStream, bool throwIfEncrypted = false) => VerifyAndReadSignedStreamAsync(inputStream, throwIfEncrypted).GetAwaiter().GetResult();

        public VerificationResult VerifyAndReadSignedArmoredString(string input, bool throwIfEncrypted = false) => VerifyAndReadSignedArmoredStringAsync(input, throwIfEncrypted).GetAwaiter().GetResult();

        #endregion Verify

        #region VerifyClear

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the clear data to</param>
        public bool VerifyClear(FileInfo inputFile, FileInfo outputFile = null) => VerifyClearAsync(inputFile, outputFile).GetAwaiter().GetResult();

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        /// <param name="outputStream">Stream to write the clear data to</param>
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        public bool VerifyClear(Stream inputStream, Stream outputStream = null) => VerifyClearAsync(inputStream, outputStream).GetAwaiter().GetResult();

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public bool VerifyClear(string input) => VerifyClearAsync(input).GetAwaiter().GetResult();

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="output">String to write the decrypted data to</param>
        public bool VerifyClear(string input, string output)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = VerifyClear(inputStream, outputStream);

                outputStream.Seek(0, SeekOrigin.Begin);
                output = outputStream.GetString();
                return verified;
            }
        }

        public bool VerifyClearFile(FileInfo inputFile) => VerifyClear(inputFile, null);

        public bool VerifyClearStream(Stream inputStream) => VerifyClear(inputStream, null);

        public bool VerifyClearArmoredString(string input) => VerifyClear(input);

        public VerificationResult VerifyAndReadClearFile(FileInfo inputFile) => VerifyAndReadClearFileAsync(inputFile).GetAwaiter().GetResult();

        public VerificationResult VerifyAndReadClearStream(Stream inputStream) => VerifyAndReadClearStreamAsync(inputStream).GetAwaiter().GetResult();

        public VerificationResult VerifyAndReadClearArmoredString(string input) => VerifyAndReadClearArmoredStringAsync(input).GetAwaiter().GetResult();

        #endregion VerifyClear
    }
}
