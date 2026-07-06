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
        private static async Task<(byte[] tampered, PGP pgpDecrypt, TestFactory testFactory)> ArrangeTamperedMessageAsync()
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            // Disable compression so the encrypted payload ends with the literal data and its MDC
            // trailer at a predictable offset, letting the tail flip below corrupt the MDC only.
            PGP pgpEncrypt = new PGP(encryptionKeys) { CompressionAlgorithm = CompressionAlgorithmTag.Uncompressed };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            using MemoryStream input = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(testFactory.Content));
            using MemoryStream encrypted = new MemoryStream();
            await pgpEncrypt.EncryptAsync(input, encrypted, armor: false);

            // Flip a bit in the ciphertext tail (inside the MDC trailer) so the integrity
            // check fails while the packet structure remains readable.
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
    }
}
