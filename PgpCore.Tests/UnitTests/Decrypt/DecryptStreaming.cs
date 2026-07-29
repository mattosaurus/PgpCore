using FluentAssertions;
using FluentAssertions.Execution;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    /// <summary>
    /// Streaming-oriented decrypt scenarios: concatenated (chunked) messages (#318) and
    /// non-seekable input streams such as network streams (#287).
    /// </summary>
    public class DecryptStreaming : TestBase
    {
        // NonSeekableStream lives on TestBase so the verify tests can use it too.

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task DecryptAsync_ConcatenatedEncryptedMessages_ShouldDecryptAllChunks(bool armor)
        {
            // Arrange - encrypt three chunks independently and concatenate, as chunked
            // uploads do (#318)
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            string[] chunks = { "first chunk|", "second chunk|", "third chunk" };

            using MemoryStream concatenated = new MemoryStream();
            foreach (string chunk in chunks)
            {
                using MemoryStream chunkIn = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(chunk));
                using MemoryStream chunkOut = new MemoryStream();
                await pgpEncrypt.EncryptAsync(chunkIn, chunkOut, armor: armor);
                chunkOut.Seek(0, SeekOrigin.Begin);
                await chunkOut.CopyToAsync(concatenated);
            }

            concatenated.Seek(0, SeekOrigin.Begin);

            // Act
            using MemoryStream decrypted = new MemoryStream();
            await pgpDecrypt.DecryptAsync(concatenated, decrypted);

            // Assert
            System.Text.Encoding.UTF8.GetString(decrypted.ToArray()).Should().Be(string.Concat(chunks));

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task EncryptAndDecryptAsync_NonSeekableStreams_ShouldRoundTrip()
        {
            // Arrange (#287 - network stream support)
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            byte[] content = System.Text.Encoding.UTF8.GetBytes(testFactory.Content);

            // Act - encrypt from a non-seekable source
            using MemoryStream encryptedBuffer = new MemoryStream();
            using (MemoryStream source = new MemoryStream(content))
                await pgpEncrypt.EncryptAsync(new NonSeekableStream(source), encryptedBuffer);

            // Decrypt from a non-seekable source
            encryptedBuffer.Seek(0, SeekOrigin.Begin);
            using MemoryStream decrypted = new MemoryStream();
            await pgpDecrypt.DecryptAsync(new NonSeekableStream(encryptedBuffer), decrypted);

            // Assert
            System.Text.Encoding.UTF8.GetString(decrypted.ToArray()).Should().Be(testFactory.Content);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task SignAsync_NonSeekableInputStream_ShouldSign()
        {
            // Arrange (#287)
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            byte[] content = System.Text.Encoding.UTF8.GetBytes(testFactory.Content);

            // Act
            using MemoryStream signedBuffer = new MemoryStream();
            using (MemoryStream source = new MemoryStream(content))
                await pgpSign.SignAsync(new NonSeekableStream(source), signedBuffer);

            signedBuffer.Seek(0, SeekOrigin.Begin);
            bool verified = await pgpVerify.VerifyAsync(signedBuffer);

            // Assert
            verified.Should().BeTrue();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task VerifyAsync_NonSeekableInputStream_ShouldVerify()
        {
            // Arrange (#287 - verification over a non-seekable stream)
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            using MemoryStream signedBuffer = new MemoryStream();
            using (MemoryStream source = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(testFactory.Content)))
                await pgpSign.SignAsync(source, signedBuffer);
            signedBuffer.Seek(0, SeekOrigin.Begin);

            // Act - verify from a non-seekable stream
            bool verified = await pgpVerify.VerifyAsync(new NonSeekableStream(signedBuffer));

            // Assert
            verified.Should().BeTrue();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task InspectAsync_NonSeekableInputStream_ShouldReportProperties()
        {
            // Arrange (#287 - inspection over a non-seekable stream)
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);

            using MemoryStream encryptedBuffer = new MemoryStream();
            using (MemoryStream source = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(testFactory.Content)))
                await pgp.EncryptAsync(source, encryptedBuffer);
            encryptedBuffer.Seek(0, SeekOrigin.Begin);

            // Act - inspect from a non-seekable stream
            var result = await pgp.InspectAsync(new NonSeekableStream(encryptedBuffer));

            // Assert
            result.IsEncrypted.Should().BeTrue();

            // Teardown
            testFactory.Teardown();
        }
    }
}
