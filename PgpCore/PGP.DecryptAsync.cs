using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.IO;
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
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptAsync(inputStream, outStream);
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
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList dataList)
                enc = dataList;
            else if (obj is PgpCompressedData compressedData)
                message = compressedData;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                if (enc != null)
                {
                    foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in enc.GetEncryptedDataObjects())
                    {
                        privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

                        if (privateKey != null)
                        {
                            pbe = publicKeyEncryptedData;
                            break;
                        }
                    }

                    if (privateKey == null)
                        throw new ArgumentException("Secret key for message not found.");

                    Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
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
                        await StreamHelper.PipeAllAsync(unc, outputStream);
                    }
                    else
                    {
                        PgpLiteralData literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        await StreamHelper.PipeAllAsync(unc, outputStream);
                    }
                }
                else if (message is PgpLiteralData literalData)
                {
                    Stream unc = literalData.GetInputStream();
                    await StreamHelper.PipeAllAsync(unc, outputStream);

                    if (pbe.IsIntegrityProtected())
                    {
                        if (!pbe.Verify())
                        {
                            throw new PgpException("Message failed integrity check.");
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
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public async Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile) => await DecryptAsync(inputFile, outputFile);

        public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream) => await DecryptAsync(inputStream, outputStream);

        public async Task<string> DecryptArmoredStringAsync(string input) => await DecryptAsync(input);

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
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptAndVerifyAsync(inputStream, outStream);
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
            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedDataList = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList dataList)
                encryptedDataList = dataList;
            else if (obj is PgpCompressedData compressedData)
                message = compressedData;
            else
                encryptedDataList = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (encryptedDataList == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                if (encryptedDataList != null)
                {
                    foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in
                             encryptedDataList.GetEncryptedDataObjects())
                    {
                        privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

                        if (privateKey != null)
                        {
                            pbe = publicKeyEncryptedData;
                            break;
                        }
                    }

                    if (privateKey == null)
                        throw new ArgumentException("Secret key for message not found.");

                    Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    message = plainFact.NextPgpObject();

                    if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                    {
                        PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                        var keyIdToVerify = pgpOnePassSignature.KeyId;

                        var verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
                            out PgpPublicKey _);
                        if (verified == false)
                            throw new PgpException("Failed to verify file.");

                        message = plainFact.NextPgpObject();
                    }
                    else if (message is PgpSignatureList pgpSignatureList)
                    {
                        PgpSignature pgpSignature = pgpSignatureList[0];
                        var keyIdToVerify = pgpSignature.KeyId;

                        var verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
                            out PgpPublicKey _);
                        if (verified == false)
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

                    long? keyIdToVerify = null;

                    if (message is PgpSignatureList pgpSignatureList)
                    {
                        keyIdToVerify = pgpSignatureList[0].KeyId;
                    }
                    else if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                    {
                        PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                        keyIdToVerify = pgpOnePassSignature.KeyId;
                    }

                    if (keyIdToVerify.HasValue)
                    {
                        var verified = Utilities.FindPublicKey(keyIdToVerify.Value, EncryptionKeys.VerificationKeys,
                            out PgpPublicKey _);
                        if (verified == false)
                            throw new PgpException("Failed to verify file.");

                        message = objectFactory.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        await StreamHelper.PipeAllAsync(unc, outputStream);
                    }
                    else
                    {
                        throw new PgpException("File was not signed.");
                    }
                }
                else if (message is PgpLiteralData literalData)
                {
                    Stream unc = literalData.GetInputStream();
                    await StreamHelper.PipeAllAsync(unc, outputStream);

                    if (pbe.IsIntegrityProtected())
                    {
                        if (!pbe.Verify())
                        {
                            throw new PgpException("Message failed integrity check.");
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
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptAndVerifyAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public async Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile) => await DecryptAndVerifyAsync(inputFile, outputFile);

        public async Task DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream) => await DecryptAndVerifyAsync(inputStream, outputStream);

        public async Task<string> DecryptArmoredStringAndVerifyAsync(string input) => await DecryptAndVerifyAsync(input);

        #endregion DecryptAndVerifyAsync
    }
}
