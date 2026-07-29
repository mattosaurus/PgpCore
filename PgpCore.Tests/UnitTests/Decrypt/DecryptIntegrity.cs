using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    /// <summary>
    /// Modification detection (MDC) behaviour: failures throw MessageIntegrityException by
    /// default, and can be tolerated via PGP.IgnoreIntegrityCheckFailure (#310, gpg's
    /// --ignore-mdc-error equivalent).
    /// </summary>
    public class DecryptIntegrity : TestBase
    {
        /// <summary>
        /// Produces an encrypted message whose modification detection trailer has been corrupted. The MDC
        /// trailer is the last packet of the plaintext regardless of compression, so flipping a bit in the
        /// ciphertext tail breaks the integrity check while leaving the payload readable.
        /// </summary>
        private static async Task<(byte[] tampered, PGP pgpDecrypt, TestFactory testFactory)> ArrangeTamperedMessageAsync(
            CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys) { CompressionAlgorithm = compressionAlgorithm };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            using MemoryStream input = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(testFactory.Content));
            using MemoryStream encrypted = new MemoryStream();
            await pgpEncrypt.EncryptAsync(input, encrypted, armor: false);

            byte[] tampered = encrypted.ToArray();
            tampered[tampered.Length - 3] ^= 0x01;

            return (tampered, pgpDecrypt, testFactory);
        }

        [Fact]
        public async Task DecryptAsync_TamperedMessage_ShouldThrowMessageIntegrityException()
        {
            // Arrange
            var (tampered, pgpDecrypt, testFactory) = await ArrangeTamperedMessageAsync();

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream tamperedStream = new MemoryStream(tampered);
                using MemoryStream output = new MemoryStream();
                await pgpDecrypt.DecryptAsync(tamperedStream, output);
            };

            // Assert
            await act.Should().ThrowAsync<MessageIntegrityException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_TamperedMessageWithIgnoreIntegrityCheckFailure_ShouldDecrypt()
        {
            // Arrange
            var (tampered, pgpDecrypt, testFactory) = await ArrangeTamperedMessageAsync();
            pgpDecrypt.IgnoreIntegrityCheckFailure = true;

            // Act
            using MemoryStream tamperedStream = new MemoryStream(tampered);
            using MemoryStream output = new MemoryStream();
            await pgpDecrypt.DecryptAsync(tamperedStream, output);

            // Assert - tampering was inside the MDC trailer, so the payload itself is intact
            System.Text.Encoding.UTF8.GetString(output.ToArray()).Should().Be(testFactory.Content);

            // Teardown
            testFactory.Teardown();
        }

        /// <summary>
        /// v8 compresses by default, and the compressed branch of the decrypt path did not run the
        /// integrity check at all - so tampering went undetected for ordinary v8 output.
        /// </summary>
        [Theory]
        [InlineData(CompressionAlgorithmTag.Zip)]
        [InlineData(CompressionAlgorithmTag.ZLib)]
        [InlineData(CompressionAlgorithmTag.BZip2)]
        public async Task DecryptAsync_TamperedCompressedMessage_ShouldThrowMessageIntegrityException(
            CompressionAlgorithmTag compressionAlgorithm)
        {
            // Arrange
            var (tampered, pgpDecrypt, testFactory) = await ArrangeTamperedMessageAsync(compressionAlgorithm);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream tamperedStream = new MemoryStream(tampered);
                using MemoryStream output = new MemoryStream();
                await pgpDecrypt.DecryptAsync(tamperedStream, output);
            };

            // Assert
            await act.Should().ThrowAsync<MessageIntegrityException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_TamperedCompressedMessageWithIgnoreIntegrityCheckFailure_ShouldDecrypt()
        {
            // Arrange
            var (tampered, pgpDecrypt, testFactory) = await ArrangeTamperedMessageAsync(CompressionAlgorithmTag.Zip);
            pgpDecrypt.IgnoreIntegrityCheckFailure = true;

            // Act
            using MemoryStream tamperedStream = new MemoryStream(tampered);
            using MemoryStream output = new MemoryStream();
            await pgpDecrypt.DecryptAsync(tamperedStream, output);

            // Assert
            System.Text.Encoding.UTF8.GetString(output.ToArray()).Should().Be(testFactory.Content);

            // Teardown
            testFactory.Teardown();
        }

        /// <summary>
        /// EncryptAndSign compresses by default too, so the decrypt-and-verify path needs the same
        /// coverage. The signature covers only the literal data, so a corrupted MDC trailer must be caught
        /// by the integrity check rather than passing as a valid message.
        /// </summary>
        [Fact]
        public async Task DecryptAndVerifyAsync_TamperedCompressedSignedMessage_ShouldThrowMessageIntegrityException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(keys) { CompressionAlgorithm = CompressionAlgorithmTag.Zip };

            using MemoryStream input = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(testFactory.Content));
            using MemoryStream encrypted = new MemoryStream();
            await pgp.EncryptAndSignAsync(input, encrypted, armor: false);

            byte[] tampered = encrypted.ToArray();
            tampered[tampered.Length - 3] ^= 0x01;

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream tamperedStream = new MemoryStream(tampered);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAndVerifyAsync(tamperedStream, output);
            };

            // Assert
            await act.Should().ThrowAsync<MessageIntegrityException>();

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(CompressionAlgorithmTag.Uncompressed)]
        [InlineData(CompressionAlgorithmTag.Zip)]
        public async Task DecryptAsync_UntamperedMessage_ShouldDecryptWithoutIntegrityError(
            CompressionAlgorithmTag compressionAlgorithm)
        {
            // Arrange - guards against an over-eager integrity check rejecting valid messages.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys) { CompressionAlgorithm = compressionAlgorithm };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            using MemoryStream input = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(testFactory.Content));
            using MemoryStream encrypted = new MemoryStream();
            await pgpEncrypt.EncryptAsync(input, encrypted, armor: false);

            // Act
            using MemoryStream encryptedInput = new MemoryStream(encrypted.ToArray());
            using MemoryStream output = new MemoryStream();
            await pgpDecrypt.DecryptAsync(encryptedInput, output);

            // Assert
            System.Text.Encoding.UTF8.GetString(output.ToArray()).Should().Be(testFactory.Content);

            // Teardown
            testFactory.Teardown();
        }
    }
}
