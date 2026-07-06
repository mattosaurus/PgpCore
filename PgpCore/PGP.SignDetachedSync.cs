using PgpCore.Abstractions;
using System.Collections.Generic;
using System.IO;

namespace PgpCore
{
    public partial class PGP : IDetachedSignSync
    {
        #region SignDetached

        /// <summary>
        /// Produce a detached signature for the file pointed to by inputFile. The output contains only the
        /// signature packet(s), not the original data.
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output file for the detached signature</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void SignDetached(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            IDictionary<string, string> headers = null) => SignDetachedAsync(inputFile, outputFile, armor, headers).GetAwaiter().GetResult();

        /// <summary>
        /// Produce a detached signature for the provided stream. The output contains only the signature
        /// packet(s), not the original data.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output stream for the detached signature</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void SignDetached(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            IDictionary<string, string> headers = null) => SignDetachedAsync(inputStream, outputStream, armor, headers).GetAwaiter().GetResult();

        /// <summary>
        /// Produce a detached signature for the provided string, returned as an armored string. The output
        /// contains only the signature packet(s), not the original data.
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public string SignDetached(
            string input,
            IDictionary<string, string> headers = null) => SignDetachedAsync(input, headers).GetAwaiter().GetResult();

        #endregion SignDetached

        #region VerifyDetached

        /// <summary>
        /// Verify a detached signature file against the original data file.
        /// </summary>
        /// <param name="inputFile">Original (unsigned) data file</param>
        /// <param name="signatureFile">Detached signature file</param>
        public bool VerifyDetached(FileInfo inputFile, FileInfo signatureFile) => VerifyDetachedAsync(inputFile, signatureFile).GetAwaiter().GetResult();

        /// <summary>
        /// Verify a detached signature stream against the original data stream.
        /// </summary>
        /// <param name="inputStream">Original (unsigned) data stream</param>
        /// <param name="signatureStream">Detached signature stream</param>
        public bool VerifyDetached(Stream inputStream, Stream signatureStream) => VerifyDetachedAsync(inputStream, signatureStream).GetAwaiter().GetResult();

        /// <summary>
        /// Verify a detached signature string against the original data string.
        /// </summary>
        /// <param name="input">Original (unsigned) data string</param>
        /// <param name="signature">Detached signature string</param>
        public bool VerifyDetached(string input, string signature) => VerifyDetachedAsync(input, signature).GetAwaiter().GetResult();

        #endregion VerifyDetached
    }
}
