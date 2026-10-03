using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IVerifyAsync
    {
        #region VerifyAsync

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Retained for signature compatibility; encrypted input now always throws. Use DecryptAndVerify for encrypted-and-signed messages.</param>
        public async Task<bool> VerifyAsync(FileInfo inputFile, FileInfo outputFile = null, bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            if (outputFile == null)
            {
                using (Stream inputStream = inputFile.OpenRead())
                {
                    return await VerifyAsync(inputStream, null, throwIfEncrypted).ConfigureAwait(false);
                }
            }
            else
            {
                return await AtomicFileOutput.VerifyAsync(outputFile, async outputStream =>
                {
                    using (Stream inputStream = inputFile.OpenRead())
                    {
                        return await VerifyAsync(inputStream, outputStream, throwIfEncrypted).ConfigureAwait(false);
                    }
                }).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="outputStream">Stream to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Retained for signature compatibility; encrypted input now always throws. Use DecryptAndVerify for encrypted-and-signed messages.</param>
        public async Task<bool> VerifyAsync(Stream inputStream, Stream outputStream = null, bool throwIfEncrypted = false)
        {
            if (inputStream == null) throw new ArgumentNullException(nameof(inputStream));
            bool verified = false;

            // Verification without extraction discards the payload as it is hashed.
            if (outputStream == null)
                outputStream = Stream.Null;

            // Verification rewinds the input (clear-sign sniff, then packet parsing) and the
            // BouncyCastle decoder requires a seekable stream, so buffer non-seekable input
            // (e.g. a network stream) up front.
            if (!inputStream.CanSeek)
            {
                using (var seekable = await SeekableInput.CopyAsync(inputStream).ConfigureAwait(false))
                    return await VerifyAsync(seekable, outputStream, throwIfEncrypted).ConfigureAwait(false);
            }

            inputStream.Seek(0, SeekOrigin.Begin);

            // Clear-signed messages use a different layout (armored clear text followed by the
            // signature) that the packet based verification below cannot parse. Detect them up
            // front and route to the clear signature verification instead.
            if (IsClearSignedInput(inputStream))
            {
                inputStream.Seek(0, SeekOrigin.Begin);
                return await VerifyClearAsync(inputStream, outputStream).ConfigureAwait(false);
            }

            inputStream.Seek(0, SeekOrigin.Begin);
            Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            // A signed message is wrapped in a compression packet whenever compression is enabled
            // (the default). Unwrap it so the inner one-pass-signature / signature packet drives
            // verification, rather than mistaking the compressed container for encrypted data.
            if (pgpObject is PgpCompressedData compressedData)
            {
                factory = new PgpObjectFactory(compressedData.GetDataStream());
                pgpObject = factory.NextPgpObject();
            }

            if (pgpObject is PgpEncryptedDataList)
            {
                // A signature inside an encrypted message cannot be verified without decrypting, so
                // there is nothing meaningful Verify can report here. Previously, when
                // throwIfEncrypted was false, this returned true if the message was merely encrypted
                // *to* a known key id - a result trivially satisfied by any sender and unrelated to
                // any signature, so it could be mistaken for successful verification. Encrypted input
                // now always throws; use DecryptAndVerify (or Decrypt then Verify) instead. The
                // throwIfEncrypted parameter is retained for signature compatibility.
                throw new ArgumentException(
                    "Input is encrypted. Use DecryptAndVerify, or decrypt the input first.", nameof(inputStream));
            }
            else if (pgpObject is PgpOnePassSignatureList onePassSignatureList)
            {
                // A message may be signed with multiple keys. Pick the first one-pass signature whose key
                // matches one of the supplied verification keys, rather than assuming the first signature.
                PgpOnePassSignature pgpOnePassSignature = null;
                PgpPublicKey validationKey = null;
                for (int i = 0; i < onePassSignatureList.Count; i++)
                {
                    if (Utilities.FindPublicKey(onePassSignatureList[i].KeyId, EncryptionKeys.VerificationKeys,
                            out validationKey))
                    {
                        pgpOnePassSignature = onePassSignatureList[i];
                        break;
                    }
                }

                PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                if (pgpOnePassSignature != null)
                {
                    pgpOnePassSignature.InitVerify(validationKey);

                    byte[] buffer = new byte[VerificationBufferSize];
                    int count;
                    while ((count = await pgpLiteralStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
                    {
                        pgpOnePassSignature.Update(buffer, 0, count);
                        await outputStream.WriteAsync(buffer, 0, count).ConfigureAwait(false);
                    }

                    PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

                    // Verify only the signature that matches the selected one-pass signature's key. Calling
                    // Verify finalizes the (stateful) message digest, so attempting it against a non-matching
                    // signature first would corrupt the digest and cause the correct signature to fail.
                    for (int i = 0; i < pgpSignatureList.Count; i++)
                    {
                        PgpSignature pgpSignature = pgpSignatureList[i];

                        if (pgpSignature.KeyId == pgpOnePassSignature.KeyId)
                        {
                            verified = pgpOnePassSignature.Verify(pgpSignature);
                            break;
                        }
                    }
                }
            }
            else if (pgpObject is PgpSignatureList signatureList)
            {
                PgpSignature pgpSignature = signatureList[0];
                PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                // Verify against public key ID and that of any sub keys
                if (Utilities.FindPublicKey(pgpSignature.KeyId, EncryptionKeys.VerificationKeys,
                        out PgpPublicKey publicKey))
                {
                    pgpSignature.InitVerify(publicKey);
                    byte[] buffer = new byte[VerificationBufferSize];
                    int count;
                    while ((count = await pgpLiteralStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
                    {
                        pgpSignature.Update(buffer, 0, count);
                        await outputStream.WriteAsync(buffer, 0, count).ConfigureAwait(false);
                    }
                    verified = pgpSignature.Verify();
                }
            }
            else
                throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

            await outputStream.FlushAsync().ConfigureAwait(false);

            // Rewinding is a convenience for callers passing a MemoryStream; a caller-supplied
            // non-seekable output (an HTTP response stream, for example) cannot be rewound.
            if (outputStream.CanSeek)
                outputStream.Seek(0, SeekOrigin.Begin);

            return (verified);
        }

        /// <summary>
        /// Determines whether the stream contains an armored clear-signed message by peeking at
        /// its first bytes. The stream position is restored before returning. Returns false for
        /// non-seekable streams as they cannot be peeked without consuming data.
        /// </summary>
        private static bool IsClearSignedInput(Stream inputStream)
        {
            if (!inputStream.CanSeek)
                return false;

            const string clearSignedHeader = "-----BEGIN PGP SIGNED MESSAGE-----";

            long position = inputStream.Position;
            try
            {
                byte[] buffer = new byte[128];
                int totalRead = 0;
                int read;
                while (totalRead < buffer.Length && (read = inputStream.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
                    totalRead += read;

                int offset = 0;
                // Skip a UTF-8 byte order mark if present
                if (totalRead >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
                    offset = 3;
                // Skip leading whitespace
                while (offset < totalRead && (buffer[offset] == ' ' || buffer[offset] == '\t' || buffer[offset] == '\r' || buffer[offset] == '\n'))
                    offset++;

                return totalRead - offset >= clearSignedHeader.Length &&
                    Encoding.ASCII.GetString(buffer, offset, clearSignedHeader.Length) == clearSignedHeader;
            }
            finally
            {
                inputStream.Position = position;
            }
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="throwIfEncrypted">Retained for signature compatibility; encrypted input now always throws. Use DecryptAndVerify for encrypted-and-signed messages.</param>
        public async Task<bool> VerifyAsync(string input, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = await input.GetStreamAsync(TextEncoding).ConfigureAwait(false))
            {
                return await VerifyAsync(inputStream, null, throwIfEncrypted).ConfigureAwait(false);
            }
        }

        public async Task<bool> VerifyFileAsync(FileInfo inputFile, bool throwIfEncrypted = false) => await VerifyAsync(inputFile, null, throwIfEncrypted).ConfigureAwait(false);

        public async Task<bool> VerifyStreamAsync(Stream inputStream, bool throwIfEncrypted = false) => await VerifyAsync(inputStream, null, throwIfEncrypted).ConfigureAwait(false);

        public async Task<bool> VerifyArmoredStringAsync(string input, bool throwIfEncrypted = false) => await VerifyAsync(input, throwIfEncrypted).ConfigureAwait(false);

        public async Task<VerificationResult> VerifyAndReadSignedFileAsync(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = inputFile.OpenRead())
                return await VerifyAndReadSignedStreamAsync(inputStream, throwIfEncrypted).ConfigureAwait(false);
        }

        public async Task<VerificationResult> VerifyAndReadSignedStreamAsync(Stream inputStream, bool throwIfEncrypted = false)
        {
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = await VerifyAsync(inputStream, outputStream, throwIfEncrypted).ConfigureAwait(false);

                return new VerificationResult(verified, await outputStream.GetStringAsync(TextEncoding).ConfigureAwait(false));
            }
        }

        public async Task<VerificationResult> VerifyAndReadSignedArmoredStringAsync(string input, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = await input.GetStreamAsync(TextEncoding).ConfigureAwait(false))
            {
                return await VerifyAndReadSignedStreamAsync(inputStream, throwIfEncrypted).ConfigureAwait(false);
            }
        }

        #endregion VerifyAsync

        #region VerifyClearAsync

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the clear data to</param>
        public async Task<bool> VerifyClearAsync(FileInfo inputFile, FileInfo outputFile = null)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            if (outputFile == null)
            {
                using (Stream inputStream = inputFile.OpenRead())
                {
                    return await VerifyClearAsync(inputStream, null).ConfigureAwait(false);
                }
            }
            else
            {
                return await AtomicFileOutput.VerifyAsync(outputFile, async outputStream =>
                {
                    using (Stream inputStream = inputFile.OpenRead())
                    {
                        return await VerifyClearAsync(inputStream, outputStream).ConfigureAwait(false);
                    }
                }).ConfigureAwait(false);
            }   
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        /// <param name="outputStream">Stream to write the clear data to</param>
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        public async Task<bool> VerifyClearAsync(Stream inputStream, Stream outputStream = null)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            // Only seekable streams have a meaningful position; reading Position on a non-seekable
            // stream such as a NetworkStream throws NotSupportedException.
            if (inputStream.CanSeek && inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream", nameof(inputStream));

            bool verified;
            bool singleLine;

            using (Stream outStream = SeekableInput.Create())
            {
                using (ArmoredInputStream armoredInputStream = new ArmoredInputStream(new NonClosingStream(inputStream)))
                {
                    singleLine = ClearTextCanonicalization.Copy(armoredInputStream, outStream);

                    // Get public key from correctly positioned stream and initialise for verification
                    PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
                    PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
                    PgpSignature pgpSignature = pgpSignatureList[0];

                    // Match the signature's key id against the supplied keys (including subkeys);
                    // fall back to the primary verification key for legacy behaviour.
                    PgpPublicKey verificationKey =
                        EncryptionKeys.VerificationKeys.FirstOrDefault(key => key.KeyId == pgpSignature.KeyId)
                        ?? EncryptionKeys.VerificationKeys.First();
                    pgpSignature.InitVerify(verificationKey);

                    ClearTextCanonicalization.UpdateSignature(pgpSignature, outStream);

                    verified = pgpSignature.Verify();
                }

                // Copy the message to the outputStream, if supplied
                if (outputStream != null)
                {
                    // Preserve the existing extraction contract for a single line.
                    if (singleLine) outStream.SetLength(Math.Max(0, outStream.Length - Environment.NewLine.Length));
                    outStream.Position = 0;
                    await outStream.CopyToAsync(outputStream).ConfigureAwait(false);
                }
            }

            return verified;
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public async Task<bool> VerifyClearAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync(TextEncoding).ConfigureAwait(false))
                return await VerifyClearAsync(inputStream, null).ConfigureAwait(false);
        }

        public async Task<bool> VerifyClearFileAsync(FileInfo inputFile) => await VerifyClearAsync(inputFile, null).ConfigureAwait(false);

        public async Task<bool> VerifyClearStreamAsync(Stream inputStream) => await VerifyClearAsync(inputStream, null).ConfigureAwait(false);

        public async Task<bool> VerifyClearArmoredStringAsync(string input) => await VerifyClearAsync(input).ConfigureAwait(false);

        public async Task<VerificationResult> VerifyAndReadClearFileAsync(FileInfo inputFile)
        {
            using (Stream inputStream = inputFile.OpenRead())
                return await VerifyAndReadClearStreamAsync(inputStream).ConfigureAwait(false);
        }

        public async Task<VerificationResult> VerifyAndReadClearStreamAsync(Stream inputStream)
        {
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = await VerifyClearAsync(inputStream, outputStream).ConfigureAwait(false);
                outputStream.Position = 0;

                return new VerificationResult(verified, await outputStream.GetStringAsync(TextEncoding).ConfigureAwait(false));
            }
        }

        public async Task<VerificationResult> VerifyAndReadClearArmoredStringAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync(TextEncoding).ConfigureAwait(false))
            {
                return await VerifyAndReadClearStreamAsync(inputStream).ConfigureAwait(false);
            }
        }

        #endregion VerifyClearAsync
    }
}
