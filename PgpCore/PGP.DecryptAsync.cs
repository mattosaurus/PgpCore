using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IDecryptAsync
    {
        private const string NotEncryptedDataMessage = "Failed to detect encrypted content format. The input does not appear to be PGP encrypted data - it may be plain text, signed-only, or clear-signed content.";

        /// <summary>Size of the buffer used to hash literal data while verifying a signature.</summary>
        private const int VerificationBufferSize = 16 * 1024;

        #region DecryptAsync

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        public async Task DecryptAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptAsync(inputStream, outStream).ConfigureAwait(false);
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <returns></returns>
        public async Task DecryptAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            // A zero-byte input contains no PGP packets; mirror it as zero-byte output.
            if (inputStream.CanSeek && inputStream.Length - inputStream.Position == 0)
                return;

            await ProcessMessagesAsync(inputStream, outputStream, DecryptMessageAsync).ConfigureAwait(false);
        }

        /// <summary>
        /// Invokes <paramref name="processMessageAsync"/> for every complete PGP message in
        /// <paramref name="inputStream"/>. Input produced by chunked or appended encryption is a
        /// concatenation of complete PGP messages (possibly in successive armor blocks), so stopping
        /// after the first message would silently discard the remainder of the data.
        /// </summary>
        private async Task ProcessMessagesAsync(Stream inputStream, Stream outputStream,
            Func<PgpEncryptedDataList, PgpObject, Stream, Task> processMessageAsync)
        {
            Stream decoderStream = Utilities.GetDecoderStream(inputStream);
            bool anyMessageProcessed = false;
            int consecutiveEmptyPasses = 0;

            while (true)
            {
                // A fresh factory is required to cross armor block boundaries: ArmoredInputStream
                // reports end-of-stream at each boundary but continues into the next block on
                // subsequent reads.
                PgpObjectFactory objFactory = new PgpObjectFactory(decoderStream);

                // the first object might be a PGP marker packet.
                PgpEncryptedDataList enc = null;
                PgpObject message = null;

                try
                {
                    PgpObject obj = objFactory.NextPgpObject();

                    if (obj == null)
                    {
                        // One empty pass can just be an armor block boundary; two in a row
                        // means the stream is exhausted.
                        consecutiveEmptyPasses++;
                        if (consecutiveEmptyPasses >= 2 || !anyMessageProcessed)
                            break;
                        continue;
                    }

                    consecutiveEmptyPasses = 0;

                    if (obj is PgpEncryptedDataList dataList)
                        enc = dataList;
                    else if (obj is PgpCompressedData compressedData)
                        message = compressedData;
                    else
                        enc = objFactory.NextPgpObject() as PgpEncryptedDataList;
                }
                catch (IOException ex)
                {
                    if (anyMessageProcessed)
                        break; // tolerate trailing non-message data after valid messages

                    // BouncyCastle throws e.g. "unknown object in stream 20" for clear-signed input.
                    throw new NotEncryptedDataException(NotEncryptedDataMessage, ex);
                }

                // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
                if (enc == null && message == null)
                {
                    if (anyMessageProcessed)
                        break;
                    throw new NotEncryptedDataException(NotEncryptedDataMessage);
                }

                await processMessageAsync(enc, message, outputStream).ConfigureAwait(false);
                anyMessageProcessed = true;
            }

            if (!anyMessageProcessed)
                throw new NotEncryptedDataException(NotEncryptedDataMessage);
        }

        private async Task DecryptMessageAsync(PgpEncryptedDataList enc, PgpObject message, Stream outputStream)
        {
            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData encryptedDataAsymmetric = null;
                PgpPbeEncryptedData encryptedDataSymmetric = null;

                if (enc != null)
                {
                    List<long> messageKeyIds = new List<long>();

                    foreach (PgpEncryptedData encryptedData in enc.GetEncryptedDataObjects())
                    {
                        if (encryptedData is PgpPublicKeyEncryptedData publicKeyEncryptedData)
                        {
                            messageKeyIds.Add(publicKeyEncryptedData.KeyId);
                            privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

                            if (privateKey != null)
                            {
                                encryptedDataAsymmetric = publicKeyEncryptedData;
                                break;
                            }
                        }

                        if (encryptedData is PgpPbeEncryptedData passwordEncryptedData)
                        {
                            encryptedDataSymmetric = passwordEncryptedData;
                        }
                    }

                    Stream clear = null;

                    if (encryptedDataAsymmetric != null)
                    {
                        clear = encryptedDataAsymmetric.GetDataStream(privateKey).DisposeWith(disposables);
                    }
                    else if (encryptedDataSymmetric != null && EncryptionKeys.SymmetricKey != null && EncryptionKeys.SymmetricKey.Length > 0)
                    {
                        clear = encryptedDataSymmetric.GetDataStreamRaw(EncryptionKeys.SymmetricKey).DisposeWith(disposables);
                    }

                    if (clear == null)
                        throw new NoDecryptionKeyException(
                            $"Decryption key for message not found. The message is encrypted to key id(s) [{string.Join(", ", messageKeyIds.Select(id => id.ToString("X")))}] but none of the supplied private keys match.");

                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    message = plainFact.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        message = plainFact.NextPgpObject();
                    }
                }

                if (message is PgpCompressedData pgpCompressedData)
                {
                    Stream compDataIn = pgpCompressedData.GetDataStream().DisposeWith(disposables);
                    PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
                    message = objectFactory.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        message = objectFactory.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        await StreamHelper.PipeAllAsync(unc, outputStream).ConfigureAwait(false);
                    }
                    else
                    {
                        PgpLiteralData literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        await StreamHelper.PipeAllAsync(unc, outputStream).ConfigureAwait(false);
                    }
                }
                else if (message is PgpLiteralData literalData)
                {
                    Stream unc = literalData.GetInputStream();
                    await StreamHelper.PipeAllAsync(unc, outputStream).ConfigureAwait(false);

                    if (encryptedDataAsymmetric != null)
                    {
                        if (encryptedDataAsymmetric.IsIntegrityProtected())
                        {
                            if (!encryptedDataAsymmetric.Verify() && !IgnoreIntegrityCheckFailure)
                            {
                                throw new MessageIntegrityException("Message failed integrity check. The encrypted data may have been tampered with.");
                            }
                        }
                    }
                    else
                    {
                        if (encryptedDataSymmetric.IsIntegrityProtected())
                        {
                            if (!encryptedDataSymmetric.Verify() && !IgnoreIntegrityCheckFailure)
                            {
                                throw new MessageIntegrityException("Message failed integrity check. The encrypted data may have been tampered with.");
                            }
                        }
                    }
                }
                else if (message is PgpOnePassSignatureList)
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                else
                    throw new PgpException("Message is not a simple encrypted file.");
            }
        }

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        public async Task<string> DecryptAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync().ConfigureAwait(false))
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptAsync(inputStream, outputStream).ConfigureAwait(false);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync().ConfigureAwait(false);
            }
        }

        public async Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile) => await DecryptAsync(inputFile, outputFile).ConfigureAwait(false);

        public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream) => await DecryptAsync(inputStream, outputStream).ConfigureAwait(false);

        public async Task<string> DecryptArmoredStringAsync(string input) => await DecryptAsync(input).ConfigureAwait(false);

        #endregion DecryptAsync

        #region DecryptAndVerifyAsync

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message. 
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file path</param>
        public async Task DecryptAndVerifyAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptAndVerifyAsync(inputStream, outStream).ConfigureAwait(false);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message. 
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public async Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            await ProcessMessagesAsync(inputStream, outputStream, DecryptAndVerifyMessageAsync).ConfigureAwait(false);
        }

        private async Task DecryptAndVerifyMessageAsync(PgpEncryptedDataList encryptedDataList, PgpObject message, Stream outputStream)
        {
            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData encryptedDataAsymmetric = null;
                PgpPbeEncryptedData encryptedDataSymmetric = null;

                // Factory that produced the current message; the signature and literal data packets that
                // follow have to be read from the same factory.
                PgpObjectFactory factory = null;

                if (encryptedDataList != null)
                {
                    List<long> messageKeyIds = new List<long>();

                    foreach (PgpEncryptedData encryptedData in encryptedDataList.GetEncryptedDataObjects())
                    {
                        if (encryptedData is PgpPublicKeyEncryptedData publicKeyEncryptedData)
                        {
                            messageKeyIds.Add(publicKeyEncryptedData.KeyId);
                            privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

                            if (privateKey != null)
                            {
                                encryptedDataAsymmetric = publicKeyEncryptedData;
                                break;
                            }
                        }

                        if (encryptedData is PgpPbeEncryptedData passwordEncryptedData)
                        {
                            encryptedDataSymmetric = passwordEncryptedData;
                        }
                    }

                    Stream clear = null;

                    if (encryptedDataAsymmetric != null)
                    {
                        clear = encryptedDataAsymmetric.GetDataStream(privateKey).DisposeWith(disposables);
                    }
                    else if (encryptedDataSymmetric != null && EncryptionKeys.SymmetricKey != null && EncryptionKeys.SymmetricKey.Length > 0)
                    {
                        clear = encryptedDataSymmetric.GetDataStreamRaw(EncryptionKeys.SymmetricKey).DisposeWith(disposables);
                    }

                    if (clear == null)
                        throw new NoDecryptionKeyException(
                            $"Decryption key for message not found. The message is encrypted to key id(s) [{string.Join(", ", messageKeyIds.Select(id => id.ToString("X")))}] but none of the supplied private keys match.");

                    factory = new PgpObjectFactory(clear);
                    message = factory.NextPgpObject();
                }

                if (message is PgpCompressedData compressedData)
                {
                    Stream compDataIn = compressedData.GetDataStream().DisposeWith(disposables);
                    factory = new PgpObjectFactory(compDataIn);
                    message = factory.NextPgpObject();
                }

                if (factory == null)
                    throw new PgpException("File was not signed.");

                // The signature is verified cryptographically against the literal data as it is written
                // out, so a signature made by an unrelated key - or over different content - fails here.
                if (message is PgpOnePassSignatureList onePassSignatureList)
                    await VerifyOnePassSignedDataAsync(onePassSignatureList, factory, outputStream).ConfigureAwait(false);
                else if (message is PgpSignatureList signatureList)
                    await VerifySignedDataAsync(signatureList, factory, outputStream).ConfigureAwait(false);
                else
                    throw new PgpException("File was not signed.");

                // The modification detection code trails the literal data, so this can only be checked
                // once the data above has been fully consumed.
                VerifyMessageIntegrity(encryptedDataAsymmetric, encryptedDataSymmetric);
            }
        }

        /// <summary>
        /// Returns the supplied verification key that made a signature with <paramref name="keyId"/>, or
        /// null when it was not supplied. The key id must match exactly: a signature can only be verified
        /// with the key that produced it, so the looser matching in
        /// <see cref="Utilities.FindPublicKey(long, System.Collections.Generic.IEnumerable{PgpPublicKey}, out PgpPublicKey)"/>
        /// (which also matches keys merely carrying a signature by that key id) is not usable here.
        /// </summary>
        private PgpPublicKey FindSigningKey(long keyId)
        {
            return EncryptionKeys.VerificationKeys?.FirstOrDefault(key => key.KeyId == keyId);
        }

        /// <summary>
        /// Verifies a one-pass signed message, writing the literal data to <paramref name="outputStream"/>
        /// as it is hashed. A message may carry several signatures (e.g. signed with multiple keys), so the
        /// first one-pass signature whose key id matches a supplied verification key is used.
        /// </summary>
        /// <exception cref="PgpException">
        /// When no supplied verification key made any of the signatures, when the expected packets are
        /// missing, or when the signature does not verify against the data.
        /// </exception>
        private async Task VerifyOnePassSignedDataAsync(PgpOnePassSignatureList onePassSignatureList,
            PgpObjectFactory factory, Stream outputStream)
        {
            PgpOnePassSignature onePassSignature = null;
            PgpPublicKey verificationKey = null;

            for (int i = 0; i < onePassSignatureList.Count; i++)
            {
                verificationKey = FindSigningKey(onePassSignatureList[i].KeyId);

                if (verificationKey != null)
                {
                    onePassSignature = onePassSignatureList[i];
                    break;
                }
            }

            if (onePassSignature == null)
                throw new PgpException("Failed to verify file.");

            if (!(factory.NextPgpObject() is PgpLiteralData literalData))
                throw new PgpException("Encrypted message contains a signed message - not literal data.");

            onePassSignature.InitVerify(verificationKey);

            Stream literalStream = literalData.GetInputStream();
            byte[] buffer = new byte[VerificationBufferSize];
            int bytesRead;

            while ((bytesRead = await literalStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                onePassSignature.Update(buffer, 0, bytesRead);
                await outputStream.WriteAsync(buffer, 0, bytesRead).ConfigureAwait(false);
            }

            if (!(factory.NextPgpObject() is PgpSignatureList signatureList))
                throw new PgpException("Failed to verify file.");

            // Verify only the signature matching the selected one-pass signature. Verify finalizes the
            // stateful digest, so attempting a non-matching signature first would corrupt it and make the
            // correct signature fail.
            bool verified = false;

            for (int i = 0; i < signatureList.Count; i++)
            {
                if (signatureList[i].KeyId == onePassSignature.KeyId)
                {
                    verified = onePassSignature.Verify(signatureList[i]);
                    break;
                }
            }

            if (!verified)
                throw new PgpException("Failed to verify file.");
        }

        /// <summary>
        /// Verifies a message whose signature precedes the literal data, writing the literal data to
        /// <paramref name="outputStream"/> as it is hashed.
        /// </summary>
        /// <exception cref="PgpException">
        /// When no supplied verification key made any of the signatures, when the expected packets are
        /// missing, or when the signature does not verify against the data.
        /// </exception>
        private async Task VerifySignedDataAsync(PgpSignatureList signatureList, PgpObjectFactory factory,
            Stream outputStream)
        {
            PgpSignature signature = null;
            PgpPublicKey verificationKey = null;

            for (int i = 0; i < signatureList.Count; i++)
            {
                verificationKey = FindSigningKey(signatureList[i].KeyId);

                if (verificationKey != null)
                {
                    signature = signatureList[i];
                    break;
                }
            }

            if (signature == null)
                throw new PgpException("Failed to verify file.");

            if (!(factory.NextPgpObject() is PgpLiteralData literalData))
                throw new PgpException("Encrypted message contains a signed message - not literal data.");

            signature.InitVerify(verificationKey);

            Stream literalStream = literalData.GetInputStream();
            byte[] buffer = new byte[VerificationBufferSize];
            int bytesRead;

            while ((bytesRead = await literalStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                signature.Update(buffer, 0, bytesRead);
                await outputStream.WriteAsync(buffer, 0, bytesRead).ConfigureAwait(false);
            }

            if (!signature.Verify())
                throw new PgpException("Failed to verify file.");
        }

        /// <summary>
        /// Checks the modification detection code of an encrypted message, honouring
        /// <see cref="IgnoreIntegrityCheckFailure"/>. Must be called only after the decrypted data has
        /// been fully read.
        /// </summary>
        private void VerifyMessageIntegrity(PgpPublicKeyEncryptedData encryptedDataAsymmetric,
            PgpPbeEncryptedData encryptedDataSymmetric)
        {
            if (encryptedDataAsymmetric != null)
            {
                if (encryptedDataAsymmetric.IsIntegrityProtected()
                    && !encryptedDataAsymmetric.Verify()
                    && !IgnoreIntegrityCheckFailure)
                {
                    throw new MessageIntegrityException("Message failed integrity check. The encrypted data may have been tampered with.");
                }
            }
            else if (encryptedDataSymmetric != null)
            {
                if (encryptedDataSymmetric.IsIntegrityProtected()
                    && !encryptedDataSymmetric.Verify()
                    && !IgnoreIntegrityCheckFailure)
                {
                    throw new MessageIntegrityException("Message failed integrity check. The encrypted data may have been tampered with.");
                }
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message. 
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        public async Task<string> DecryptAndVerifyAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync().ConfigureAwait(false))
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptAndVerifyAsync(inputStream, outputStream).ConfigureAwait(false);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync().ConfigureAwait(false);
            }
        }

        public async Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile) => await DecryptAndVerifyAsync(inputFile, outputFile).ConfigureAwait(false);

        public async Task DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream) => await DecryptAndVerifyAsync(inputStream, outputStream).ConfigureAwait(false);

        public async Task<string> DecryptArmoredStringAndVerifyAsync(string input) => await DecryptAndVerifyAsync(input).ConfigureAwait(false);

        #endregion DecryptAndVerifyAsync
    }
}
