using FluentAssertions;
using FluentAssertions.Execution;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Errors
{
    /// <summary>
    /// Tests that common failure modes surface as specific PgpCore exception types
    /// with actionable messages, rather than raw BouncyCastle errors.
    /// </summary>
    public class ErrorHandling : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public async Task DecryptAsync_WithWrongPassphrase_ShouldThrowIncorrectPassphraseException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, "wrong-passphrase");
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            string encrypted = await pgpEncrypt.EncryptAsync(testFactory.Content);

            // Act
            Func<Task> act = async () => await pgpDecrypt.DecryptAsync(encrypted);

            // Assert
            await act.Should().ThrowAsync<IncorrectPassphraseException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void EncryptionKeys_WithInvalidPublicKeyMaterial_ShouldThrowInvalidKeyMaterialException()
        {
            // Act
            Action act = () => new EncryptionKeys("this is not a pgp key");

            // Assert
            act.Should().Throw<InvalidKeyMaterialException>();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public async Task DecryptAsync_ClearSignedMessage_ShouldThrowNotEncryptedDataException(KeyType keyType)
        {
            // Arrange - a clear-signed (not encrypted) message routed to Decrypt
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgpSign = new PGP(signingKeys);
            string clearSigned = await pgpSign.ClearSignAsync(testFactory.Content);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            Func<Task> act = async () => await pgpDecrypt.DecryptAsync(clearSigned);

            // Assert - clear-signed data is not decryptable; the error should say so
            await act.Should().ThrowAsync<NotEncryptedDataException>();

            // Teardown
            testFactory.Teardown();
        }
    }
}
