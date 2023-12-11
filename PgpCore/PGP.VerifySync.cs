using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.IO;
using System.Linq;

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
        public bool Verify(FileInfo inputFile, FileInfo outputFile = null, bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            if (outputFile == null)
            {
                using (Stream inputStream = inputFile.OpenRead())
                {
                    return Verify(inputStream, null, throwIfEncrypted);
                }
            }
            else
            {
                using (Stream inputStream = inputFile.OpenRead())
                using (Stream outputStream = outputFile.OpenWrite())
                {
                    return Verify(inputStream, outputStream, throwIfEncrypted);
                }
            }
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="outputStream">Stream to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public bool Verify(Stream inputStream, Stream outputStream = null, bool throwIfEncrypted = false)
        {
            bool verified = false;

            // If no output stream provided just write to memory stream and discard
            if (outputStream == null)
                outputStream = new MemoryStream();

            using (StreamWriter contentStreamWriter = new StreamWriter(outputStream, inputStream.GetEncoding(), 1024, true))
            {
                inputStream.Seek(0, SeekOrigin.Begin);
                Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
                PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
                PgpObject pgpObject = factory.NextPgpObject();

                if (pgpObject is PgpCompressedData)
                {
                    PgpPublicKeyEncryptedData publicKeyEncryptedData = Utilities.ExtractPublicKeyEncryptedData(encodedFile);

                    // Verify against public key ID and that of any sub keys
                    var keyIdToVerify = publicKeyEncryptedData.KeyId;
                    verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
                        out PgpPublicKey _);
                }
                else if (pgpObject is PgpEncryptedDataList dataList)
                {
                    if (throwIfEncrypted)
                    {
                        throw new ArgumentException("Input is encrypted. Decrypt the input first.");
                    }
                    PgpPublicKeyEncryptedData publicKeyEncryptedData = Utilities.ExtractPublicKey(dataList);
                    var keyIdToVerify = publicKeyEncryptedData.KeyId;
                    // If we encounter an encrypted packet, verify with the encryption keys used instead
                    // TODO does this even make sense? maybe throw exception instead, or try to decrypt first
                    verified = Utilities.FindPublicKeyInKeyRings(keyIdToVerify, EncryptionKeys.PublicKeyRings.Select(keyRing => keyRing.PgpPublicKeyRing), out PgpPublicKey _);
                }
                else if (pgpObject is PgpOnePassSignatureList onePassSignatureList)
                {
                    PgpOnePassSignature pgpOnePassSignature = onePassSignatureList[0];
                    PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                    Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                    // Verify against public key ID and that of any sub keys
                    var keyIdToVerify = pgpOnePassSignature.KeyId;
                    if (Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
                            out PgpPublicKey validationKey))
                    {
                        pgpOnePassSignature.InitVerify(validationKey);

                        int ch;
                        while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                        {
                            pgpOnePassSignature.Update((byte)ch);
                            contentStreamWriter.Write((char)ch);
                        }

                        PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

                        for (int i = 0; i < pgpSignatureList.Count; i++)
                        {
                            PgpSignature pgpSignature = pgpSignatureList[i];

                            if (pgpOnePassSignature.Verify(pgpSignature))
                            {
                                verified = true;
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
                        foreach (PgpSignature _ in publicKey.GetSignatures())
                        {
                            if (!verified)
                            {
                                pgpSignature.InitVerify(publicKey);

                                int ch;
                                while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                                {
                                    pgpSignature.Update((byte)ch);
                                    contentStreamWriter.Write((char)ch);
                                }

                                verified = pgpSignature.Verify();
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
                else
                    throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

                contentStreamWriter.Flush();
                outputStream.Seek(0, SeekOrigin.Begin);
            }

            return (verified);
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public bool Verify(string input, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = input.GetStream())
            {
                return Verify(inputStream, null, throwIfEncrypted);
            }
        }

        public bool VerifyFile(FileInfo inputFile, bool throwIfEncrypted = false) => Verify(inputFile, null, throwIfEncrypted);

        public bool VerifyStream(Stream inputStream, bool throwIfEncrypted = false) => Verify(inputStream, null, throwIfEncrypted);

        public bool VerifyArmoredString(string input, bool throwIfEncrypted = false) => Verify(input, throwIfEncrypted);

        public VerificationResult VerifyAndReadSignedFile(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = inputFile.OpenRead())
                return VerifyAndReadSignedStream(inputStream, throwIfEncrypted);
        }

        public VerificationResult VerifyAndReadSignedStream(Stream inputStream, bool throwIfEncrypted = false)
        {
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = Verify(inputStream, outputStream, throwIfEncrypted);

                return new VerificationResult(verified, outputStream.GetString());
            }
        }

        public VerificationResult VerifyAndReadSignedArmoredString(string input, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = input.GetStream())
                return VerifyAndReadSignedStream(inputStream, throwIfEncrypted);
        }

        #endregion Verify

        #region VerifyClear

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the clear data to</param>
        public bool VerifyClear(FileInfo inputFile, FileInfo outputFile = null)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            if (outputFile == null)
            {
                using (Stream inputStream = inputFile.OpenRead())
                {
                    return VerifyClear(inputStream, null);
                }
            }
            else
            {
                using (Stream inputStream = inputFile.OpenRead())
                using (Stream outputStream = outputFile.OpenWrite())
                {
                    return VerifyClear(inputStream, outputStream);
                }
            }
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        /// <param name="outputStream">Stream to write the clear data to</param>
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        public bool VerifyClear(Stream inputStream, Stream outputStream = null)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            bool verified;

            using (MemoryStream outStream = new MemoryStream())
            {
                using (ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream))
                {
                    MemoryStream lineOut = new MemoryStream();
                    byte[] lineSep = LineSeparator;
                    int lookAhead = ReadInputLine(lineOut, armoredInputStream);

                    // Read past message to signature and store message in stream
                    if (lookAhead != -1 && armoredInputStream.IsClearText())
                    {
                        byte[] line = lineOut.ToArray();
                        outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStream.Write(lineSep, 0, lineSep.Length);

                        while (lookAhead != -1 && armoredInputStream.IsClearText())
                        {
                            lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

                            line = lineOut.ToArray();
                            outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                            outStream.Write(lineSep, 0, lineSep.Length);
                        }
                    }
                    else if (lookAhead != -1)
                    {
                        byte[] line = lineOut.ToArray();
                        outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStream.Write(lineSep, 0, lineSep.Length);
                    }

                    // Get public key from correctly positioned stream and initialise for verification
                    PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
                    PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
                    PgpSignature pgpSignature = pgpSignatureList[0];

                    pgpSignature.InitVerify(EncryptionKeys.VerificationKeys.First());

                    // Read through message again and calculate signature
                    outStream.Position = 0;
                    lookAhead = ReadInputLine(lineOut, outStream);

                    ProcessLine(pgpSignature, lineOut.ToArray());

                    while (lookAhead != -1)
                    {
                        lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

                        pgpSignature.Update((byte)'\r');
                        pgpSignature.Update((byte)'\n');

                        ProcessLine(pgpSignature, lineOut.ToArray());
                    }

                    verified = pgpSignature.Verify();
                }

                // Copy the message to the outputStream, if supplied
                if (outputStream != null)
                {
                    outStream.Position = 0;
                    outStream.CopyTo(outputStream);
                }
            }

            return verified;
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public bool VerifyClear(string input)
        {
            using (Stream inputStream = input.GetStream())
                return VerifyClear(inputStream, null);
        }

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

        public VerificationResult VerifyAndReadClearFile(FileInfo inputFile)
        {
            using (Stream inputStream = inputFile.OpenRead())
                return VerifyAndReadClearStream(inputStream);
        }

        public VerificationResult VerifyAndReadClearStream(Stream inputStream)
        {
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = VerifyClear(inputStream, outputStream);
                outputStream.Position = 0;

                return new VerificationResult(verified, outputStream.GetString());
            }
        }

        public VerificationResult VerifyAndReadClearArmoredString(string input)
        {
            using (Stream inputStream = input.GetStream())
                return VerifyAndReadClearStream(inputStream);
        }

        #endregion VerifyClear
    }
}
