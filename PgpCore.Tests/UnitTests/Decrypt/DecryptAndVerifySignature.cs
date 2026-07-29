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
        /// <summary>Where the signature packet sits relative to the literal data it covers.</summary>
        private enum SignaturePlacement
        {
            /// <summary>One-pass signature header before the data, signature packet after it.</summary>
            OnePass,

            /// <summary>Signature packet before the data, with no one-pass header.</summary>
            Prefix
        }

        /// <summary>
        /// Builds an encrypted, signed message with deliberate control over each part, so individual
        /// verification paths and their failure modes can be exercised.
        /// </summary>
        /// <param name="signedContent">The content the signature digests.</param>
        /// <param name="deliveredContent">The content written to the literal data packet.</param>
        /// <param name="signingKeys">Keys used to sign; defaults to <paramref name="recipientKeys"/>.</param>
        /// <param name="includeLiteralData">When false, no literal data packet follows the signature.</param>
        /// <param name="includeTrailingSignature">
        /// One-pass only: when false, the trailing signature packet is omitted.
        /// </param>
        /// <param name="symmetricKey">When supplied, the message is encrypted to this passphrase key
        /// instead of to a public key.</param>
        private static byte[] BuildMessage(
            EncryptionKeys recipientKeys,
            byte[] signedContent,
            byte[] deliveredContent,
            SignaturePlacement placement = SignaturePlacement.OnePass,
            EncryptionKeys signingKeys = null,
            bool includeLiteralData = true,
            bool includeTrailingSignature = true,
            byte[] symmetricKey = null)
        {
            signingKeys = signingKeys ?? recipientKeys;
            PgpSecretKey secretKey = signingKeys.SigningSecretKey;
            PgpPrivateKey privateKey = signingKeys.SigningPrivateKey;

            using MemoryStream output = new MemoryStream();

            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());

            if (symmetricKey != null)
                encryptedDataGenerator.AddMethodRaw(symmetricKey, HashAlgorithmTag.Sha256);
            else
                encryptedDataGenerator.AddMethod(recipientKeys.EncryptKeys.First());

            using (Stream encryptedStream = encryptedDataGenerator.Open(output, new byte[1 << 16]))
            {
                PgpSignatureGenerator signatureGenerator =
                    new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
                signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);

                if (placement == SignaturePlacement.OnePass)
                    signatureGenerator.GenerateOnePassVersion(false).Encode(encryptedStream);

                // Digest whatever content the caller nominated - not necessarily what is written below.
                signatureGenerator.Update(signedContent);

                if (placement == SignaturePlacement.Prefix)
                    signatureGenerator.Generate().Encode(encryptedStream);

                if (includeLiteralData)
                {
                    PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                    using Stream literalStream = literalDataGenerator.Open(encryptedStream, PgpLiteralData.Binary,
                        DEFAULTNAME, deliveredContent.Length, DateTime.UtcNow);
                    literalStream.Write(deliveredContent, 0, deliveredContent.Length);
                }

                if (placement == SignaturePlacement.OnePass && includeTrailingSignature)
                    signatureGenerator.Generate().Encode(encryptedStream);
            }

            return output.ToArray();
        }

        private static async Task<(EncryptionKeys keys, TestFactory testFactory)> ArrangeKeysAsync(
            KeyType keyType = KeyType.Known)
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            return (keys, testFactory);
        }

        private static Func<Task> DecryptAndVerify(EncryptionKeys keys, byte[] message)
        {
            PGP pgp = new PGP(keys);
            return async () =>
            {
                using MemoryStream input = new MemoryStream(message);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAndVerifyAsync(input, output);
            };
        }

        #region One-pass signatures

        [Fact]
        public async Task DecryptAndVerifyAsync_SignatureMadeOverDifferentContent_ShouldThrow()
        {
            // Arrange - the signature is made by a key the verifier trusts, but over other content, so
            // a key-id presence check alone would wrongly report this message as verified.
            var (keys, testFactory) = await ArrangeKeysAsync();

            byte[] forged = BuildMessage(keys,
                signedContent: Encoding.UTF8.GetBytes("the content that was signed"),
                deliveredContent: Encoding.UTF8.GetBytes("the content that was delivered"));

            // Act
            Func<Task> act = DecryptAndVerify(keys, forged);

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
            var (keys, testFactory) = await ArrangeKeysAsync();

            byte[] content = Encoding.UTF8.GetBytes("the content that was delivered");
            byte[] message = BuildMessage(keys, signedContent: content, deliveredContent: content);

            // Act
            PGP pgp = new PGP(keys);
            using MemoryStream input = new MemoryStream(message);
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(input, output);

            // Assert
            output.ToArray().Should().Equal(content);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_OnePassSignatureWithoutLiteralData_ShouldThrow()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            byte[] content = Encoding.UTF8.GetBytes("content");

            byte[] message = BuildMessage(keys, content, content, includeLiteralData: false);

            // Act
            Func<Task> act = DecryptAndVerify(keys, message);

            // Assert
            await act.Should().ThrowAsync<PgpException>()
                .Where(e => e.Message == "Encrypted message contains a signed message - not literal data.");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_OnePassSignatureWithoutTrailingSignature_ShouldThrow()
        {
            // Arrange - the one-pass header promises a signature that never arrives.
            var (keys, testFactory) = await ArrangeKeysAsync();
            byte[] content = Encoding.UTF8.GetBytes("content");

            byte[] message = BuildMessage(keys, content, content, includeTrailingSignature: false);

            // Act
            Func<Task> act = DecryptAndVerify(keys, message);

            // Assert
            await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "Failed to verify file.");

            // Teardown
            testFactory.Teardown();
        }

        #endregion One-pass signatures

        #region Signatures preceding the literal data

        [Fact]
        public async Task DecryptAndVerifyAsync_PrefixSignatureOverTheDeliveredContent_ShouldVerify()
        {
            // Arrange - some implementations emit the signature packet before the literal data rather
            // than using a one-pass header.
            var (keys, testFactory) = await ArrangeKeysAsync();

            byte[] content = Encoding.UTF8.GetBytes("prefix signed content");
            byte[] message = BuildMessage(keys, content, content, SignaturePlacement.Prefix);

            // Act
            PGP pgp = new PGP(keys);
            using MemoryStream input = new MemoryStream(message);
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(input, output);

            // Assert
            output.ToArray().Should().Equal(content);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_PrefixSignatureOverDifferentContent_ShouldThrow()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();

            byte[] message = BuildMessage(keys,
                signedContent: Encoding.UTF8.GetBytes("the content that was signed"),
                deliveredContent: Encoding.UTF8.GetBytes("the content that was delivered"),
                placement: SignaturePlacement.Prefix);

            // Act
            Func<Task> act = DecryptAndVerify(keys, message);

            // Assert
            await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "Failed to verify file.");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_PrefixSignatureFromKeyNotSupplied_ShouldThrow()
        {
            // Arrange - signed by a key the verifier does not hold.
            var (recipientKeys, recipientFactory) = await ArrangeKeysAsync();
            var (signingKeys, signingFactory) = await ArrangeKeysAsync(KeyType.KnownGpg);

            byte[] content = Encoding.UTF8.GetBytes("content");
            byte[] message = BuildMessage(recipientKeys, content, content, SignaturePlacement.Prefix,
                signingKeys: signingKeys);

            // Act
            Func<Task> act = DecryptAndVerify(recipientKeys, message);

            // Assert
            await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "Failed to verify file.");

            // Teardown
            recipientFactory.Teardown();
            signingFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_PrefixSignatureWithoutLiteralData_ShouldThrow()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            byte[] content = Encoding.UTF8.GetBytes("content");

            byte[] message = BuildMessage(keys, content, content, SignaturePlacement.Prefix,
                includeLiteralData: false);

            // Act
            Func<Task> act = DecryptAndVerify(keys, message);

            // Assert
            await act.Should().ThrowAsync<PgpException>()
                .Where(e => e.Message == "Encrypted message contains a signed message - not literal data.");

            // Teardown
            testFactory.Teardown();
        }

        #endregion Signatures preceding the literal data

        #region Symmetric (passphrase) encryption

        private static async Task<(EncryptionKeys keys, TestFactory testFactory)> ArrangeSymmetricKeysAsync()
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Symmetric, FileType.Known);

            // Guard: only KeyType.Symmetric populates SymmetricKey, and a null key would silently fall
            // back to public key encryption, making the symmetric assertions below vacuous.
            testFactory.SymmetricKey.Should().NotBeNullOrEmpty();

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password)
            {
                SymmetricKey = testFactory.SymmetricKey
            };

            return (keys, testFactory);
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_SymmetricallyEncryptedSignedMessage_ShouldVerify()
        {
            // Arrange - encrypted to a passphrase key rather than a public key, so the integrity check
            // runs against the symmetric data packet.
            var (keys, testFactory) = await ArrangeSymmetricKeysAsync();

            byte[] content = Encoding.UTF8.GetBytes("symmetrically encrypted signed content");
            byte[] message = BuildMessage(keys, content, content, symmetricKey: testFactory.SymmetricKey);

            // Act
            PGP pgp = new PGP(keys);
            using MemoryStream input = new MemoryStream(message);
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(input, output);

            // Assert
            output.ToArray().Should().Equal(content);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_SymmetricMessageWithTamperedIntegrityTrailer_ShouldThrowMessageIntegrityException()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeSymmetricKeysAsync();

            byte[] content = Encoding.UTF8.GetBytes("symmetrically encrypted signed content");
            byte[] message = BuildMessage(keys, content, content, symmetricKey: testFactory.SymmetricKey);
            // The modification detection trailer sits at the end of the plaintext, so corrupting the
            // ciphertext tail breaks the integrity check while leaving the signature intact.
            message[message.Length - 3] ^= 0x01;

            // Act
            Func<Task> act = DecryptAndVerify(keys, message);

            // Assert
            await act.Should().ThrowAsync<MessageIntegrityException>();

            // Teardown
            testFactory.Teardown();
        }

        #endregion Symmetric (passphrase) encryption

        #region Message integrity

        [Fact]
        public async Task DecryptAndVerifyAsync_TamperedIntegrityTrailer_ShouldThrowMessageIntegrityException()
        {
            // Arrange - v8 compresses by default, and DecryptAndVerify previously skipped the integrity
            // check entirely for compressed messages.
            var (keys, testFactory) = await ArrangeKeysAsync();

            byte[] content = Encoding.UTF8.GetBytes("content whose integrity trailer is corrupted");
            byte[] message = BuildMessage(keys, content, content);
            message[message.Length - 3] ^= 0x01;

            // Act
            Func<Task> act = DecryptAndVerify(keys, message);

            // Assert
            await act.Should().ThrowAsync<MessageIntegrityException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_TamperedIntegrityTrailerWithIgnoreIntegrityCheckFailure_ShouldVerify()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();

            byte[] content = Encoding.UTF8.GetBytes("content whose integrity trailer is corrupted");
            byte[] message = BuildMessage(keys, content, content);
            message[message.Length - 3] ^= 0x01;

            // Act
            PGP pgp = new PGP(keys) { IgnoreIntegrityCheckFailure = true };
            using MemoryStream input = new MemoryStream(message);
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(input, output);

            // Assert - the signature still covers the payload, which is intact
            output.ToArray().Should().Equal(content);

            // Teardown
            testFactory.Teardown();
        }

        #endregion Message integrity

        #region Concatenated messages

        [Fact]
        public async Task DecryptAndVerifyAsync_ConcatenatedSignedMessages_ShouldReturnEveryMessage()
        {
            // Arrange - chunked encryption produces a concatenation of complete PGP messages. Decrypt
            // handles this; DecryptAndVerify used to return only the first chunk without erroring (#318).
            var (keys, testFactory) = await ArrangeKeysAsync();
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
            await untrustedFactory.ArrangeAsync(KeyType.KnownGpg, FileType.Known);

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

        #endregion Concatenated messages

        #region Argument and content guards

        [Fact]
        public async Task DecryptAndVerifyAsync_NullInputStream_ShouldThrowArgumentNullException()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            PGP pgp = new PGP(keys);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAndVerifyAsync(null, output);
            };

            // Assert
            await act.Should().ThrowAsync<ArgumentNullException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_NullOutputStream_ShouldThrowArgumentNullException()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            PGP pgp = new PGP(keys);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(new byte[] { 0x01 });
                await pgp.DecryptAndVerifyAsync(input, null);
            };

            // Assert
            await act.Should().ThrowAsync<ArgumentNullException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_EncryptedButUnsignedMessage_ShouldThrow()
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            PGP pgp = new PGP(keys);

            using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes("unsigned content"));
            using MemoryStream encrypted = new MemoryStream();
            await pgp.EncryptAsync(input, encrypted, armor: false);
            encrypted.Position = 0;

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAndVerifyAsync(encrypted, output);
            };

            // Assert
            await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "File was not signed.");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_SignedButUnencryptedMessage_ShouldThrowNotEncryptedDataException()
        {
            // Arrange - a structurally valid PGP message that simply is not encrypted. Compression is
            // disabled so the signature packets sit at the top level of the stream.
            var (keys, testFactory) = await ArrangeKeysAsync();
            PGP pgpSign = new PGP(keys) { CompressionAlgorithm = CompressionAlgorithmTag.Uncompressed };
            PGP pgpDecrypt = new PGP(keys);

            using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes("signed but not encrypted"));
            using MemoryStream signed = new MemoryStream();
            await pgpSign.SignAsync(input, signed, armor: false);
            // SignAsync closes the output stream; ToArray remains valid on a closed MemoryStream.
            byte[] signedMessage = signed.ToArray();

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream signedInput = new MemoryStream(signedMessage);
                using MemoryStream output = new MemoryStream();
                await pgpDecrypt.DecryptAsync(signedInput, output);
            };

            // Assert
            await act.Should().ThrowAsync<NotEncryptedDataException>();

            // Teardown
            testFactory.Teardown();
        }

        #endregion Argument and content guards
    }
}
