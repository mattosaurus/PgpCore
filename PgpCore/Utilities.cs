using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PgpCore
{
    /// <remarks>Basic utility class.</remarks>
    public sealed class Utilities
    {
        private Utilities()
        {
        }

        public static MPInteger[] DsaSigToMpi(
            byte[] encoding)
        {
            DerInteger i1, i2;

            try
            {
                Asn1Sequence s = (Asn1Sequence)Asn1Object.FromByteArray(encoding);

                i1 = (DerInteger)s[0];
                i2 = (DerInteger)s[1];
            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding signature", e);
            }

            return new MPInteger[] { new MPInteger(i1.Value), new MPInteger(i2.Value) };
        }

        public static MPInteger[] RsaSigToMpi(
            byte[] encoding)
        {
            return new MPInteger[] { new MPInteger(new BigInteger(1, encoding)) };
        }

        public static string GetDigestName(
            HashAlgorithmTag hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithmTag.Sha1:
                    return "SHA1";
                case HashAlgorithmTag.MD2:
                    return "MD2";
                case HashAlgorithmTag.MD5:
                    return "MD5";
                case HashAlgorithmTag.RipeMD160:
                    return "RIPEMD160";
                case HashAlgorithmTag.Sha224:
                    return "SHA224";
                case HashAlgorithmTag.Sha256:
                    return "SHA256";
                case HashAlgorithmTag.Sha384:
                    return "SHA384";
                case HashAlgorithmTag.Sha512:
                    return "SHA512";
                default:
                    throw new PgpException("unknown hash algorithm tag in GetDigestName: " + hashAlgorithm);
            }
        }

        public static string GetSignatureName(
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm)
        {
            string encAlg;
            switch (keyAlgorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    encAlg = "RSA";
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    encAlg = "DSA";
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                    encAlg = "ECDH";
                    break;
                case PublicKeyAlgorithmTag.ECDsa:
                    encAlg = "ECDSA";
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt: // in some malformed cases.
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    encAlg = "ElGamal";
                    break;
                default:
                    throw new PgpException("unknown algorithm tag in signature:" + keyAlgorithm);
            }

            return GetDigestName(hashAlgorithm) + "with" + encAlg;
        }

        public static string GetSymmetricCipherName(
                SymmetricKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
                case SymmetricKeyAlgorithmTag.Null:
                    return null;
                case SymmetricKeyAlgorithmTag.TripleDes:
                    return "DESEDE";
                case SymmetricKeyAlgorithmTag.Idea:
                    return "IDEA";
                case SymmetricKeyAlgorithmTag.Cast5:
                    return "CAST5";
                case SymmetricKeyAlgorithmTag.Blowfish:
                    return "Blowfish";
                case SymmetricKeyAlgorithmTag.Safer:
                    return "SAFER";
                case SymmetricKeyAlgorithmTag.Des:
                    return "DES";
                case SymmetricKeyAlgorithmTag.Aes128:
                    return "AES";
                case SymmetricKeyAlgorithmTag.Aes192:
                    return "AES";
                case SymmetricKeyAlgorithmTag.Aes256:
                    return "AES";
                case SymmetricKeyAlgorithmTag.Twofish:
                    return "Twofish";
                case SymmetricKeyAlgorithmTag.Camellia128:
                    return "Camellia";
                case SymmetricKeyAlgorithmTag.Camellia192:
                    return "Camellia";
                case SymmetricKeyAlgorithmTag.Camellia256:
                    return "Camellia";
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }
        }

        public static int GetKeySize(SymmetricKeyAlgorithmTag algorithm)
        {
            int keySize;
            switch (algorithm)
            {
                case SymmetricKeyAlgorithmTag.Des:
                    keySize = 64;
                    break;
                case SymmetricKeyAlgorithmTag.Idea:
                case SymmetricKeyAlgorithmTag.Cast5:
                case SymmetricKeyAlgorithmTag.Blowfish:
                case SymmetricKeyAlgorithmTag.Safer:
                case SymmetricKeyAlgorithmTag.Aes128:
                case SymmetricKeyAlgorithmTag.Camellia128:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.TripleDes:
                case SymmetricKeyAlgorithmTag.Aes192:
                case SymmetricKeyAlgorithmTag.Camellia192:
                    keySize = 192;
                    break;
                case SymmetricKeyAlgorithmTag.Aes256:
                case SymmetricKeyAlgorithmTag.Twofish:
                case SymmetricKeyAlgorithmTag.Camellia256:
                    keySize = 256;
                    break;
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }

            return keySize;
        }

        public static KeyParameter MakeKey(
            SymmetricKeyAlgorithmTag algorithm,
            byte[] keyBytes)
        {
            string algName = GetSymmetricCipherName(algorithm);

            return ParameterUtilities.CreateKeyParameter(algName, keyBytes);
        }

        public static KeyParameter MakeRandomKey(
            SymmetricKeyAlgorithmTag algorithm,
            SecureRandom random)
        {
            int keySize = GetKeySize(algorithm);
            byte[] keyBytes = new byte[(keySize + 7) / 8];
            random.NextBytes(keyBytes);
            return MakeKey(algorithm, keyBytes);
        }

        public static KeyParameter MakeKeyFromPassPhrase(
            SymmetricKeyAlgorithmTag algorithm,
            S2k s2k,
            char[] passPhrase)
        {
            int keySize = GetKeySize(algorithm);
            byte[] pBytes = Strings.ToByteArray(new string(passPhrase));
            byte[] keyBytes = new byte[(keySize + 7) / 8];

            int generatedBytes = 0;
            int loopCount = 0;

            while (generatedBytes < keyBytes.Length)
            {
                IDigest digest;
                if (s2k != null)
                {
                    string digestName = GetDigestName(s2k.HashAlgorithm);

                    try
                    {
                        digest = DigestUtilities.GetDigest(digestName);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("can't find S2k digest", e);
                    }

                    for (int i = 0; i != loopCount; i++)
                    {
                        digest.Update(0);
                    }

                    byte[] iv = s2k.GetIV();

                    switch (s2k.Type)
                    {
                        case S2k.Simple:
                            digest.BlockUpdate(pBytes, 0, pBytes.Length);
                            break;
                        case S2k.Salted:
                            digest.BlockUpdate(iv, 0, iv.Length);
                            digest.BlockUpdate(pBytes, 0, pBytes.Length);
                            break;
                        case S2k.SaltedAndIterated:
                            long count = s2k.IterationCount;
                            digest.BlockUpdate(iv, 0, iv.Length);
                            digest.BlockUpdate(pBytes, 0, pBytes.Length);

                            count -= iv.Length + pBytes.Length;

                            while (count > 0)
                            {
                                if (count < iv.Length)
                                {
                                    digest.BlockUpdate(iv, 0, (int)count);
                                    break;
                                }
                                else
                                {
                                    digest.BlockUpdate(iv, 0, iv.Length);
                                    count -= iv.Length;
                                }

                                if (count < pBytes.Length)
                                {
                                    digest.BlockUpdate(pBytes, 0, (int)count);
                                    count = 0;
                                }
                                else
                                {
                                    digest.BlockUpdate(pBytes, 0, pBytes.Length);
                                    count -= pBytes.Length;
                                }
                            }
                            break;
                        default:
                            throw new PgpException("unknown S2k type: " + s2k.Type);
                    }
                }
                else
                {
                    try
                    {
                        digest = DigestUtilities.GetDigest("MD5");

                        for (int i = 0; i != loopCount; i++)
                        {
                            digest.Update(0);
                        }

                        digest.BlockUpdate(pBytes, 0, pBytes.Length);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("can't find MD5 digest", e);
                    }
                }

                byte[] dig = DigestUtilities.DoFinal(digest);

                if (dig.Length > (keyBytes.Length - generatedBytes))
                {
                    Array.Copy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
                }
                else
                {
                    Array.Copy(dig, 0, keyBytes, generatedBytes, dig.Length);
                }

                generatedBytes += dig.Length;

                loopCount++;
            }

            Array.Clear(pBytes, 0, pBytes.Length);

            return MakeKey(algorithm, keyBytes);
        }

        /// <summary>Write out the passed in file as a literal data packet.</summary>
        public static async Task WriteFileToLiteralDataAsync(
            Stream output,
            char fileType,
            FileInfo file)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime);
            await PipeFileContentsAsync(file, pOut, 4096);
            lData.Close();
        }

        /// <summary>Write out the passed in file as a literal data packet.</summary>
        public static void WriteFileToLiteralData(
            Stream output,
            char fileType,
            FileInfo file)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime);
            PipeFileContents(file, pOut, 4096);
            lData.Close();
        }

        /// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
        public static async Task WriteFileToLiteralDataAsync(
            Stream output,
            char fileType,
            FileInfo file,
            byte[] buffer)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer);
            await PipeFileContentsAsync(file, pOut, buffer.Length);
            lData.Close();
        }

        /// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
        public static void WriteFileToLiteralData(
            Stream output,
            char fileType,
            FileInfo file,
            byte[] buffer)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer);
            PipeFileContents(file, pOut, buffer.Length);
            lData.Close();
        }

        public static async Task WriteStreamToLiteralDataAsync(
            Stream output,
            char fileType,
            Stream input,
            string name)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
            await PipeStreamContentsAsync(input, pOut, 4096);
            lData.Close();
        }

        public static void WriteStreamToLiteralData(
            Stream output,
            char fileType,
            Stream input,
            string name)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
            PipeStreamContents(input, pOut, 4096);
            lData.Close();
        }

        public static async Task WriteStreamToLiteralDataAsync(
            Stream output,
            char fileType,
            Stream input,
            byte[] buffer,
            string name)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, name, DateTime.Now, buffer);
            await PipeStreamContentsAsync(input, pOut, buffer.Length);
            lData.Close();
        }

        public static void WriteStreamToLiteralData(
            Stream output,
            char fileType,
            Stream input,
            byte[] buffer,
            string name)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            Stream pOut = lData.Open(output, fileType, name, DateTime.Now, buffer);
            PipeStreamContents(input, pOut, buffer.Length);
            lData.Close();
        }

        /// <summary>
        /// Opens a key ring file and returns first available sub-key suitable for encryption.
        /// If such sub-key is not found, return master key that can encrypt.
        /// </summary>
        /// <param name="inputStream">Input stream containing the public key contents</param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
        {
            using (Stream inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

                // we just loop through the collection till we find a key suitable for encryption, in the real
                // world you would probably want to be a bit smarter about this.
                // iterate through the key rings.
                foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
                {
                    List<PgpPublicKey> keys = kRing.GetPublicKeys()
                        .Cast<PgpPublicKey>()
                        .Where(k => k.IsEncryptionKey).ToList();

                    const int encryptKeyFlags = PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage;

                    foreach (PgpPublicKey key in keys.Where(k => k.Version >= 4 && k.IsMasterKey))
                    {
                        foreach (PgpSignature s in key.GetSignatures())
                        {
                            if (s.HasSubpackets && s.GetHashedSubPackets().GetKeyFlags() == encryptKeyFlags)
                                return key;
                        }
                    }

                    if (keys.Any())
                        return keys.First();
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Parses a public key
        /// </summary>
        /// <param name="publicKey">The plain text value of the public key</param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(string publicKey)
        {

            if (string.IsNullOrEmpty(publicKey))
                throw new FileNotFoundException(String.Format("Public key was not provided"));

            return ReadPublicKey(publicKey.GetStream());
        }

        /// <summary>
        /// Parses a public key
        /// </summary>
        /// <param name="publicKeyFile">The path to the public key file</param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(FileInfo publicKeyFile)
        {
            if (!publicKeyFile.Exists)
                throw new FileNotFoundException(String.Format("File {0} was not found", publicKeyFile));
            using (FileStream fs = publicKeyFile.OpenRead())
                return ReadPublicKey(fs);
        }

        private static async Task PipeFileContentsAsync(FileInfo file, Stream pOut, int bufSize)
        {
            using (FileStream inputStream = file.OpenRead())
            {
                byte[] buf = new byte[bufSize];

                int len;
                while ((len = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
                {
                    await pOut.WriteAsync(buf, 0, len);
                }
            }
        }

        private static void PipeFileContents(FileInfo file, Stream pOut, int bufSize)
        {
            using (FileStream inputStream = file.OpenRead())
            {
                byte[] buf = new byte[bufSize];

                int len;
                while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
                {
                    pOut.Write(buf, 0, len);
                }
            }
        }

        private static async Task PipeStreamContentsAsync(Stream input, Stream pOut, int bufSize)
        {
            byte[] buf = new byte[bufSize];

            int len;
            while ((len = await input.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await pOut.WriteAsync(buf, 0, len);
            }
        }

        private static void PipeStreamContents(Stream input, Stream pOut, int bufSize)
        {
            byte[] buf = new byte[bufSize];

            int len;
            while ((len = input.Read(buf, 0, buf.Length)) > 0)
            {
                pOut.Write(buf, 0, len);
            }
        }

        private const int ReadAhead = 60;

        private static bool IsPossiblyBase64(
            int ch)
        {
            return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
                    || (ch == '\r') || (ch == '\n');
        }

        /// <summary>
        /// Return either an ArmoredInputStream or a BcpgInputStream based on whether
        /// the initial characters of the stream are binary PGP encodings or not.
        /// </summary>
        public static Stream GetDecoderStream(
            Stream inputStream)
        {
            // TODO Remove this restriction?
            if (!inputStream.CanSeek)
                throw new ArgumentException("inputStream must be seek-able", "inputStream");

            long markedPos = inputStream.Position;

            int ch = inputStream.ReadByte();
            if ((ch & 0x80) != 0)
            {
                inputStream.Position = markedPos;

                return inputStream;
            }
            else
            {
                if (!IsPossiblyBase64(ch))
                {
                    inputStream.Position = markedPos;

                    return new ArmoredInputStream(inputStream);
                }

                byte[] buf = new byte[ReadAhead];
                int count = 1;
                int index = 1;

                buf[0] = (byte)ch;
                while (count != ReadAhead && (ch = inputStream.ReadByte()) >= 0)
                {
                    if (!IsPossiblyBase64(ch))
                    {
                        inputStream.Position = markedPos;

                        return new ArmoredInputStream(inputStream);
                    }

                    if (ch != '\n' && ch != '\r')
                    {
                        buf[index++] = (byte)ch;
                    }

                    count++;
                }

                inputStream.Position = markedPos;

                //
                // nothing but new lines, little else, assume regular armoring
                //
                if (count < 4)
                {
                    return new ArmoredInputStream(inputStream);
                }

                //
                // test our non-blank data
                //
                byte[] firstBlock = new byte[8];
                Array.Copy(buf, 0, firstBlock, 0, firstBlock.Length);
                byte[] decoded = Base64.Decode(firstBlock);

                //
                // it's a base64 PGP block.
                //
                bool hasHeaders = (decoded[0] & 0x80) == 0;

                return new ArmoredInputStream(inputStream, hasHeaders);
            }
        }

        public static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(System.IO.Stream encodedFile)
        {
            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(encodedFile);
            PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKey(encryptedDataList);
            return publicKeyED;
        }

        public static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(PgpEncryptedDataList encryptedDataList)
        {
            PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKey(encryptedDataList);
            return publicKeyED;
        }

        public static PgpObject ProcessCompressedMessage(PgpObject message)
        {
            PgpCompressedData compressedData = (PgpCompressedData)message;
            Stream compressedDataStream = compressedData.GetDataStream();
            PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedDataStream);
            message = CheckForOnePassSignatureList(message, compressedFactory);
            return message;
        }

        public static PgpObject CheckForOnePassSignatureList(PgpObject message, PgpObjectFactory compressedFactory)
        {
            message = compressedFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
            {
                message = compressedFactory.NextPgpObject();
            }
            return message;
        }

        public static PgpObject SkipSignatureList(PgpObjectFactory compressedFactory)
        {
            var message = compressedFactory.NextPgpObject();
            while (message is PgpOnePassSignatureList || message is PgpSignatureList)
            {
                message = compressedFactory.NextPgpObject();
            }
            return message;
        }

        internal static PgpObject GetClearCompressedMessage(PgpPublicKeyEncryptedData publicKeyED, EncryptionKeys encryptionKeys)
        {
            PgpObjectFactory clearFactory = GetClearDataStream(encryptionKeys.PrivateKey, publicKeyED);
            PgpObject message = clearFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
                message = clearFactory.NextPgpObject();
            return message;
        }

        public static PgpObjectFactory GetClearDataStream(PgpPrivateKey privateKey, PgpPublicKeyEncryptedData publicKeyED)
        {
            Stream clearStream = publicKeyED.GetDataStream(privateKey);
            PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
            return clearFactory;
        }

        public static PgpPublicKeyEncryptedData ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
        {
            PgpPublicKeyEncryptedData publicKeyED = null;
            foreach (PgpPublicKeyEncryptedData privateKeyED in encryptedDataList.GetEncryptedDataObjects())
            {
                if (privateKeyED != null)
                {
                    publicKeyED = privateKeyED;
                    break;
                }
            }
            return publicKeyED;
        }

        public static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
        {
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            PgpEncryptedDataList encryptedDataList;

            if (pgpObject is PgpEncryptedDataList)
            {
                encryptedDataList = (PgpEncryptedDataList)pgpObject;
            }
            else
            {
                encryptedDataList = (PgpEncryptedDataList)factory.NextPgpObject();
            }
            return encryptedDataList;
        }

        public static PgpOnePassSignatureList GetPgpOnePassSignatureList(Stream encodedFile)
        {
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            PgpOnePassSignatureList pgpOnePassSignatureList;

            if (pgpObject is PgpOnePassSignatureList)
            {
                pgpOnePassSignatureList = (PgpOnePassSignatureList)pgpObject;
            }
            else
            {
                pgpOnePassSignatureList = (PgpOnePassSignatureList)factory.NextPgpObject();
            }

            return pgpOnePassSignatureList;
        }
    }
}
