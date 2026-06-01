using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Tests.UnitTests
{
    public abstract class TestBase
    {
#if NETFRAMEWORK
        public const string VERSION = "BouncyCastle.NET Cryptography (net461) v2.4.0+83ebf4a805";
#else
        public const string VERSION = "BouncyCastle.NET Cryptography (net6.0) v2.4.0+83ebf4a805";
#endif
        public const string DEFAULTNAME = "name";
        public const string TESTNAME = "Test Name";
        public const string TESTHEADERKEY = "Test Header";
        public const string TESTHEADERVALUE = "Test Value";

        public static IEnumerable<object[]> GetCompressionAlgorithmTags()
        {
            foreach (CompressionAlgorithmTag compressionAlgorithmTag in TestHelper.GetEnumValues<CompressionAlgorithmTag>())
            {
                yield return new object[] { compressionAlgorithmTag };
            }
        }

        public static IEnumerable<object[]> GetHashAlgorithmTags()
        {
            foreach (HashAlgorithmTag hashAlgorithmTag in TestHelper.GetEnumValues<HashAlgorithmTag>())
            {
                yield return new object[] { hashAlgorithmTag };
            }
        }

        public static IEnumerable<object[]> GetSymmetricAlgorithmTags()
        {
            foreach (SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag in TestHelper.GetEnumValues<SymmetricKeyAlgorithmTag>())
            {
                // Exclude as null is not for encryption and safer is not supported.
                if (symmetricKeyAlgorithmTag == SymmetricKeyAlgorithmTag.Null || symmetricKeyAlgorithmTag == SymmetricKeyAlgorithmTag.Safer)
                    continue;

                yield return new object[] { symmetricKeyAlgorithmTag };
            }
        }

        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }
            throw new ArgumentException("No encryption key found in public key ring.");
        }

        public static IEnumerable<T> GetEnumValues<T>() where T : struct, IConvertible
        {
            foreach (T enumValue in Enum.GetValues(typeof(T)))
            {
                yield return enumValue;
            }
        }

        /// <summary>
        /// Builds a message encrypted to a single recipient and signed by two distinct keys, mirroring a
        /// GnuPG <c>gpg -r recipient -u signer1 -u signer2</c> message. The two signatures are emitted as a
        /// single one-pass signature list, which is what exercises multi-signature verification.
        /// </summary>
        public static byte[] CreateEncryptedAndDoubleSignedMessage(
            string content,
            Stream recipientPublicKeyStream,
            Stream firstSignerPrivateKeyStream, string firstSignerPassword,
            Stream secondSignerPrivateKeyStream, string secondSignerPassword,
            bool armor = false)
        {
            PgpPublicKey encryptionKey = ReadPublicKey(recipientPublicKeyStream);

            PgpSecretKey firstSecretKey = ReadSigningSecretKey(firstSignerPrivateKeyStream);
            PgpPrivateKey firstPrivateKey = firstSecretKey.ExtractPrivateKey(firstSignerPassword.ToCharArray());
            PgpSecretKey secondSecretKey = ReadSigningSecretKey(secondSignerPrivateKeyStream);
            PgpPrivateKey secondPrivateKey = secondSecretKey.ExtractPrivateKey(secondSignerPassword.ToCharArray());

            byte[] data = Encoding.UTF8.GetBytes(content);

            using (MemoryStream output = new MemoryStream())
            {
                if (armor)
                {
                    // The ArmoredOutputStream writes its footer (checksum + end marker) on dispose, so it must
                    // be closed before output.ToArray() is read. Scoping it to its own using block guarantees
                    // that ordering and also disposes it on exception paths.
                    using (ArmoredOutputStream armoredOut = new ArmoredOutputStream(output))
                    {
                        WriteEncryptedAndDoubleSignedMessage(armoredOut, encryptionKey,
                            firstSecretKey, firstPrivateKey, secondSecretKey, secondPrivateKey, data);
                    }
                }
                else
                {
                    WriteEncryptedAndDoubleSignedMessage(output, encryptionKey,
                        firstSecretKey, firstPrivateKey, secondSecretKey, secondPrivateKey, data);
                }

                return output.ToArray();
            }
        }

        private static void WriteEncryptedAndDoubleSignedMessage(
            Stream messageOut,
            PgpPublicKey encryptionKey,
            PgpSecretKey firstSecretKey, PgpPrivateKey firstPrivateKey,
            PgpSecretKey secondSecretKey, PgpPrivateKey secondPrivateKey,
            byte[] data)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
            encryptedDataGenerator.AddMethod(encryptionKey);

            using (Stream encryptedOut = encryptedDataGenerator.Open(messageOut, new byte[1 << 16]))
            using (Stream compressedOut = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip).Open(encryptedOut))
            {
                PgpSignatureGenerator firstSignatureGenerator =
                    CreateSignatureGenerator(firstSecretKey, firstPrivateKey);
                PgpSignatureGenerator secondSignatureGenerator =
                    CreateSignatureGenerator(secondSecretKey, secondPrivateKey);

                // One-pass signature headers are written outermost-first (nested).
                firstSignatureGenerator.GenerateOnePassVersion(true).Encode(compressedOut);
                secondSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

                PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                using (Stream literalOut = literalDataGenerator.Open(
                    compressedOut, PgpLiteralData.Binary, "message.txt", data.Length, DateTime.UtcNow))
                {
                    literalOut.Write(data, 0, data.Length);
                    firstSignatureGenerator.Update(data);
                    secondSignatureGenerator.Update(data);
                }

                // Signatures are emitted in reverse order to the one-pass headers (innermost first).
                secondSignatureGenerator.Generate().Encode(compressedOut);
                firstSignatureGenerator.Generate().Encode(compressedOut);
            }
        }

        /// <summary>
        /// Builds a signed (not encrypted, not compressed) message carrying two distinct one-pass signatures,
        /// mirroring a GnuPG <c>gpg --sign -u signer1 -u signer2</c> message. Leaving it uncompressed ensures
        /// the message parses as a one-pass signature list, which is what exercises multi-signature verification
        /// in the Verify code path.
        /// </summary>
        public static byte[] CreateDoubleSignedMessage(
            string content,
            Stream firstSignerPrivateKeyStream, string firstSignerPassword,
            Stream secondSignerPrivateKeyStream, string secondSignerPassword,
            bool armor = false)
        {
            PgpSecretKey firstSecretKey = ReadSigningSecretKey(firstSignerPrivateKeyStream);
            PgpPrivateKey firstPrivateKey = firstSecretKey.ExtractPrivateKey(firstSignerPassword.ToCharArray());
            PgpSecretKey secondSecretKey = ReadSigningSecretKey(secondSignerPrivateKeyStream);
            PgpPrivateKey secondPrivateKey = secondSecretKey.ExtractPrivateKey(secondSignerPassword.ToCharArray());

            byte[] data = Encoding.UTF8.GetBytes(content);

            using (MemoryStream output = new MemoryStream())
            {
                if (armor)
                {
                    // The ArmoredOutputStream writes its footer on dispose, so it must close before
                    // output.ToArray() is read; its own using block guarantees that ordering.
                    using (ArmoredOutputStream armoredOut = new ArmoredOutputStream(output))
                    {
                        WriteDoubleSignedMessage(armoredOut,
                            firstSecretKey, firstPrivateKey, secondSecretKey, secondPrivateKey, data);
                    }
                }
                else
                {
                    WriteDoubleSignedMessage(output,
                        firstSecretKey, firstPrivateKey, secondSecretKey, secondPrivateKey, data);
                }

                return output.ToArray();
            }
        }

        private static void WriteDoubleSignedMessage(
            Stream messageOut,
            PgpSecretKey firstSecretKey, PgpPrivateKey firstPrivateKey,
            PgpSecretKey secondSecretKey, PgpPrivateKey secondPrivateKey,
            byte[] data)
        {
            PgpSignatureGenerator firstSignatureGenerator = CreateSignatureGenerator(firstSecretKey, firstPrivateKey);
            PgpSignatureGenerator secondSignatureGenerator = CreateSignatureGenerator(secondSecretKey, secondPrivateKey);

            // One-pass signature headers are written outermost-first (nested).
            firstSignatureGenerator.GenerateOnePassVersion(true).Encode(messageOut);
            secondSignatureGenerator.GenerateOnePassVersion(false).Encode(messageOut);

            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
            using (Stream literalOut = literalDataGenerator.Open(
                messageOut, PgpLiteralData.Binary, "message.txt", data.Length, DateTime.UtcNow))
            {
                literalOut.Write(data, 0, data.Length);
                firstSignatureGenerator.Update(data);
                secondSignatureGenerator.Update(data);
            }

            // Signatures are emitted in reverse order to the one-pass headers (innermost first).
            secondSignatureGenerator.Generate().Encode(messageOut);
            firstSignatureGenerator.Generate().Encode(messageOut);
        }

        private static PgpSignatureGenerator CreateSignatureGenerator(PgpSecretKey secretKey, PgpPrivateKey privateKey)
        {
            PgpSignatureGenerator signatureGenerator =
                new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);
            return signatureGenerator;
        }

        private static PgpSecretKey ReadSigningSecretKey(Stream privateKeyStream)
        {
            PgpSecretKeyRingBundle bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
            foreach (PgpSecretKeyRing keyRing in bundle.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                        return key;
                }
            }
            throw new ArgumentException("No signing key found in secret key ring.");
        }
    }
}
