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

            // Input produced by chunked/appended encryption is a concatenation of complete PGP
            // messages (possibly in successive armor blocks); decrypt each in turn.
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
                    throw new NotEncryptedDataException("Failed to detect encrypted content format. The input does not appear to be PGP encrypted data - it may be plain text, signed-only, or clear-signed content.", ex);
                }

                // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
                if (enc == null && message == null)
                {
                    if (anyMessageProcessed)
                        break;
                    throw new NotEncryptedDataException("Failed to detect encrypted content format. The input does not appear to be PGP encrypted data - it may be plain text, signed-only, or clear-signed content.");
                }

                await DecryptMessageAsync(enc, message, outputStream).ConfigureAwait(false);
                anyMessageProcessed = true;
            }

            if (!anyMessageProcessed)
                throw new NotEncryptedDataException("Failed to detect encrypted content format. The input does not appear to be PGP encrypted data - it may be plain text, signed-only, or clear-signed content.");
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
            PgpObjectFactory objFactory = new PgpObjectFactory(Utilities.GetDecoderStream(inputStream));

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedDataList = null;
            PgpObject message = null;

            try
            {
                PgpObject obj = objFactory.NextPgpObject();

                if (obj is PgpEncryptedDataList dataList)
                    encryptedDataList = dataList;
                else if (obj is PgpCompressedData compressedData)
                    message = compressedData;
                else
                    encryptedDataList = objFactory.NextPgpObject() as PgpEncryptedDataList;
            }
            catch (IOException ex)
            {
                // BouncyCastle throws e.g. "unknown object in stream 20" for clear-signed input.
                throw new NotEncryptedDataException("Failed to detect encrypted content format. The input does not appear to be PGP encrypted data - it may be plain text, signed-only, or clear-signed content.", ex);
            }

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (encryptedDataList == null && message == null)
                throw new NotEncryptedDataException("Failed to detect encrypted content format. The input does not appear to be PGP encrypted data - it may be plain text, signed-only, or clear-signed content.");

            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData encryptedDataAsymmetric = null;
                PgpPbeEncryptedData encryptedDataSymmetric = null;
                
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

                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    message = plainFact.NextPgpObject();

                    if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                    {
                        // A message may carry multiple signatures (e.g. signed with several keys). This is a
                        // key-id presence check, not a cryptographic signature verification: it confirms that
                        // at least one signature was made by a key id matching one of the supplied
                        // verification keys, regardless of the signature's position in the list.
                        bool signerKeyFound = Utilities.FindPublicKey(pgpOnePassSignatureList,
                            EncryptionKeys.VerificationKeys, out PgpPublicKey _);
                        if (signerKeyFound == false)
                            throw new PgpException("Failed to verify file.");

                        message = plainFact.NextPgpObject();
                    }
                    else if (message is PgpSignatureList pgpSignatureList)
                    {
                        bool signerKeyFound = Utilities.FindPublicKey(pgpSignatureList,
                            EncryptionKeys.VerificationKeys, out PgpPublicKey _);
                        if (signerKeyFound == false)
                            throw new PgpException("Failed to verify file.");

                        message = plainFact.NextPgpObject();
                    }
                    else if (!(message is PgpCompressedData))
                        throw new PgpException("File was not signed.");
                }

                if (message is PgpCompressedData cData)
                {
                    Stream compDataIn = cData.GetDataStream().DisposeWith(disposables);
                    PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
                    message = objectFactory.NextPgpObject();

                    bool isSigned = true;
                    bool signerKeyFound = false;

                    // A message may carry multiple signatures (e.g. signed with several keys). This is a
                    // key-id presence check, not a cryptographic signature verification: it confirms that at
                    // least one signature was made by a key id matching one of the supplied verification keys,
                    // regardless of the signature's position in the list.
                    if (message is PgpSignatureList pgpSignatureList)
                    {
                        signerKeyFound = Utilities.FindPublicKey(pgpSignatureList,
                            EncryptionKeys.VerificationKeys, out PgpPublicKey _);
                    }
                    else if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                    {
                        signerKeyFound = Utilities.FindPublicKey(pgpOnePassSignatureList,
                            EncryptionKeys.VerificationKeys, out PgpPublicKey _);
                    }
                    else
                    {
                        isSigned = false;
                    }

                    if (isSigned)
                    {
                        if (signerKeyFound == false)
                            throw new PgpException("Failed to verify file.");

                        message = objectFactory.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        await StreamHelper.PipeAllAsync(unc, outputStream).ConfigureAwait(false);
                    }
                    else
                    {
                        throw new PgpException("File was not signed.");
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
                else
                    throw new PgpException("File was not signed.");
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
