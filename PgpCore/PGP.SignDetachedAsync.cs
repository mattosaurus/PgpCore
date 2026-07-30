using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IDetachedSignAsync
    {
        #region SignDetachedAsync

        /// <summary>
        /// Produce a detached signature for the file pointed to by inputFile. The output contains only the
        /// signature packet(s), not the original data.
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output file for the detached signature</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task SignDetachedAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            IDictionary<string, string> headers = null)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");
            if (headers == null)
                headers = new Dictionary<string, string>();

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outputStream = outputFile.OpenWrite())
            {
                await SignDetachedAsync(inputStream, outputStream, armor, headers).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Produce a detached signature for the provided stream. The output contains only the signature
        /// packet(s), not the original data.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output stream for the detached signature</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task SignDetachedAsync(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            IDictionary<string, string> headers = null)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");
            if (headers == null)
                headers = new Dictionary<string, string>();
            if (inputStream.CanSeek && inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream", nameof(inputStream));

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers, AddVersionHeader))
                {
                    await OutputDetachedSignedAsync(inputStream, armoredOutputStream).ConfigureAwait(false);
                }
            }
            else
                await OutputDetachedSignedAsync(inputStream, outputStream).ConfigureAwait(false);
        }

        /// <summary>
        /// Produce a detached signature for the provided string, returned as an armored string. The output
        /// contains only the signature packet(s), not the original data.
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task<string> SignDetachedAsync(
            string input,
            IDictionary<string, string> headers = null)
        {
            if (headers == null)
                headers = new Dictionary<string, string>();

            using (Stream inputStream = await input.GetStreamAsync(TextEncoding).ConfigureAwait(false))
            using (Stream outputStream = new MemoryStream())
            {
                await SignDetachedAsync(inputStream, outputStream, true, headers).ConfigureAwait(false);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync(TextEncoding).ConfigureAwait(false);
            }
        }

        private async Task OutputDetachedSignedAsync(Stream inputStream, Stream outputStream)
        {
            PgpSignatureGenerator signatureGenerator = InitDetachedSignatureGenerator();

            int length;
            byte[] buf = new byte[BufferSize];
            while ((length = await inputStream.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
            {
                signatureGenerator.Update(buf, 0, length);
            }

            using (BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(outputStream))
            {
                signatureGenerator.Generate().Encode(bcpgOutputStream);
            }
        }

        private PgpSignatureGenerator InitDetachedSignatureGenerator()
        {
            PublicKeyAlgorithmTag tag = EncryptionKeys.SigningSecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, EncryptionKeys.SigningPrivateKey);
            foreach (string userId in EncryptionKeys.SigningSecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.AddSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }

            return pgpSignatureGenerator;
        }

        #endregion SignDetachedAsync

        #region VerifyDetachedAsync

        /// <summary>
        /// Verify a detached signature file against the original data file.
        /// </summary>
        /// <param name="inputFile">Original (unsigned) data file</param>
        /// <param name="signatureFile">Detached signature file</param>
        public async Task<bool> VerifyDetachedAsync(FileInfo inputFile, FileInfo signatureFile)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (signatureFile == null)
                throw new ArgumentNullException(nameof(signatureFile));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");
            if (!signatureFile.Exists)
                throw new FileNotFoundException($"Signature file [{signatureFile.FullName}] does not exist.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream signatureStream = signatureFile.OpenRead())
            {
                return await VerifyDetachedAsync(inputStream, signatureStream).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Verify a detached signature stream against the original data stream.
        /// </summary>
        /// <param name="inputStream">Original (unsigned) data stream</param>
        /// <param name="signatureStream">Detached signature stream</param>
        public async Task<bool> VerifyDetachedAsync(Stream inputStream, Stream signatureStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (signatureStream == null)
                throw new ArgumentNullException(nameof(signatureStream));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            Stream decoderStream = PgpUtilities.GetDecoderStream(signatureStream);
            PgpObjectFactory factory = new PgpObjectFactory(decoderStream);

            PgpSignatureList signatureList;
            PgpObject pgpObject = factory.NextPgpObject();
            if (pgpObject is PgpCompressedData compressedData)
            {
                PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedData.GetDataStream());
                signatureList = compressedFactory.NextPgpObject() as PgpSignatureList;
            }
            else
            {
                signatureList = pgpObject as PgpSignatureList;
            }

            if (signatureList == null || signatureList.Count == 0)
                return false;

            // Pick the first signature whose key id matches one of the supplied verification keys.
            PgpSignature pgpSignature = null;
            PgpPublicKey publicKey = null;
            for (int i = 0; i < signatureList.Count; i++)
            {
                if (Utilities.FindPublicKey(signatureList[i].KeyId, EncryptionKeys.VerificationKeys, out publicKey))
                {
                    pgpSignature = signatureList[i];
                    break;
                }
            }

            if (pgpSignature == null)
                return false;

            pgpSignature.InitVerify(publicKey);

            int length;
            byte[] buf = new byte[BufferSize];
            while ((length = await inputStream.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
            {
                pgpSignature.Update(buf, 0, length);
            }

            return pgpSignature.Verify();
        }

        /// <summary>
        /// Verify a detached signature string against the original data string.
        /// </summary>
        /// <param name="input">Original (unsigned) data string</param>
        /// <param name="signature">Detached signature string</param>
        public async Task<bool> VerifyDetachedAsync(string input, string signature)
        {
            using (Stream inputStream = await input.GetStreamAsync(TextEncoding).ConfigureAwait(false))
            using (Stream signatureStream = await signature.GetStreamAsync(TextEncoding).ConfigureAwait(false))
            {
                return await VerifyDetachedAsync(inputStream, signatureStream).ConfigureAwait(false);
            }
        }

        #endregion VerifyDetachedAsync
    }
}
