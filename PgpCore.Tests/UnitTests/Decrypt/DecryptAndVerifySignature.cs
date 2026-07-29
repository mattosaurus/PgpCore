using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    /// <summary>
    /// DecryptAndVerify must verify signatures cryptographically rather than merely confirming that
    /// the signer's key id is one of the supplied verification keys, and must consume every message in
    /// the stream rather than stopping after the first (#318).
    /// </summary>
    public class DecryptAndVerifySignature : TestBase
    {
        /// <summary>
        /// Builds an encrypted, one-pass signed message in which the signature is genuinely made by
        /// <paramref name="testFactory"/>'s signing key but digests <paramref name="signedContent"/>,
        /// while the literal data packet carries <paramref name="deliveredContent"/>. Passing the same
        /// value for both produces an ordinary valid message.
        /// </summary>
        private static byte[] BuildSignedEncryptedMessage(TestFactory testFactory, byte[] signedContent,
            byte[] deliveredContent)
        {
            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PgpSecretKey secretKey = keys.SigningSecretKey;
            PgpPrivateKey privateKey = keys.SigningPrivateKey;
            PgpPublicKey encryptionKey = keys.EncryptKeys.First();

            using MemoryStream output = new MemoryStream();

            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
            encryptedDataGenerator.AddMethod(encryptionKey);

            using (Stream encryptedStream = encryptedDataGenerator.Open(output, new byte[1 << 16]))
            {
                PgpSignatureGenerator signatureGenerator =
                    new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
                signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);
                signatureGenerator.GenerateOnePassVersion(false).Encode(encryptedStream);

                PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                using (Stream literalStream = literalDataGenerator.Open(encryptedStream, PgpLiteralData.Binary,
                           DEFAULTNAME, deliveredContent.Length, DateTime.UtcNow))
                {
                    literalStream.Write(deliveredContent, 0, deliveredContent.Length);
                }

                // Digest whatever content the caller nominated - not necessarily what was written above.
                signatureGenerator.Update(signedContent);
                signatureGenerator.Generate().Encode(encryptedStream);
            }

            return output.ToArray();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_SignatureMadeOverDifferentContent_ShouldThrow()
        {
            // Arrange - the signature is made by a key the verifier trusts, but over other content, so
            // a key-id presence check alone would wrongly report this message as verified.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            byte[] forged = BuildSignedEncryptedMessage(testFactory,
                signedContent: Encoding.UTF8.GetBytes("the content that was signed"),
                deliveredContent: Encoding.UTF8.GetBytes("the content that was delivered"));

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(decryptionKeys);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(forged);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAndVerifyAsync(input, output);
            };

            // Assert
            await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "Failed to verify file.");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_SignatureMadeOverTheDeliveredContent_ShouldVerify()
        {
            // Arrange - same construction as the forged case, proving the difference is the signed
            // content and not the way the message is assembled.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            byte[] content = Encoding.UTF8.GetBytes("the content that was delivered");
            byte[] message = BuildSignedEncryptedMessage(testFactory, signedContent: content, deliveredContent: content);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(decryptionKeys);

            // Act
            using MemoryStream input = new MemoryStream(message);
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(input, output);

            // Assert
            output.ToArray().Should().Equal(content);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_ConcatenatedSignedMessages_ShouldReturnEveryMessage()
        {
            // Arrange - chunked encryption produces a concatenation of complete PGP messages. Decrypt
            // handles this; DecryptAndVerify used to return only the first chunk without erroring (#318).
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(keys);

            byte[] payload = new byte[3 * 8 * 1024 + 517];
            new Random(4242).NextBytes(payload);
            const int chunkSize = 8 * 1024;

            using MemoryStream concatenated = new MemoryStream();
            for (int offset = 0; offset < payload.Length; offset += chunkSize)
            {
                int length = Math.Min(chunkSize, payload.Length - offset);
                using MemoryStream chunkInput = new MemoryStream(payload, offset, length);
                using MemoryStream chunkOutput = new MemoryStream();
                await pgp.EncryptAndSignAsync(chunkInput, chunkOutput, armor: false);
                chunkOutput.Position = 0;
                await chunkOutput.CopyToAsync(concatenated);
            }
            concatenated.Position = 0;

            // Act
            using MemoryStream decrypted = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(concatenated, decrypted);

            // Assert
            decrypted.ToArray().Should().Equal(payload);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_ConcatenatedMessagesWhereOneIsSignedByAnUntrustedKey_ShouldThrow()
        {
            // Arrange - a later message signed by a key the verifier does not hold must not be waved
            // through just because the first message verified.
            TestFactory trustedFactory = new TestFactory();
            TestFactory untrustedFactory = new TestFactory();
            await trustedFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            await untrustedFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            // Both messages are encrypted to the trusted recipient, but signed by different keys.
            EncryptionKeys trustedKeys = new EncryptionKeys(trustedFactory.PublicKey, trustedFactory.PrivateKey, trustedFactory.Password);
            EncryptionKeys untrustedSigningKeys = new EncryptionKeys(trustedFactory.PublicKey, untrustedFactory.PrivateKey, untrustedFactory.Password);
            PGP trustedPgp = new PGP(trustedKeys);
            PGP untrustedPgp = new PGP(untrustedSigningKeys);

            using MemoryStream concatenated = new MemoryStream();

            using (MemoryStream first = new MemoryStream(Encoding.UTF8.GetBytes("first message")))
            using (MemoryStream firstEncrypted = new MemoryStream())
            {
                await trustedPgp.EncryptAndSignAsync(first, firstEncrypted, armor: false);
                firstEncrypted.Position = 0;
                await firstEncrypted.CopyToAsync(concatenated);
            }

            using (MemoryStream second = new MemoryStream(Encoding.UTF8.GetBytes("second message")))
            using (MemoryStream secondEncrypted = new MemoryStream())
            {
                await untrustedPgp.EncryptAndSignAsync(second, secondEncrypted, armor: false);
                secondEncrypted.Position = 0;
                await secondEncrypted.CopyToAsync(concatenated);
            }

            concatenated.Position = 0;

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream output = new MemoryStream();
                await trustedPgp.DecryptAndVerifyAsync(concatenated, output);
            };

            // Assert
            await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "Failed to verify file.");

            // Teardown
            trustedFactory.Teardown();
            untrustedFactory.Teardown();
        }
    }
}
