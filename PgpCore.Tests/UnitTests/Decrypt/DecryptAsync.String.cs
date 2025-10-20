using FluentAssertions.Execution;
using FluentAssertions;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    public class DecryptAsync_String : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptAsync(encryptedContent);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_DecryptLargeEncryptedMessage_ShouldDecryptMessage()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.GeneratedLarge);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptAsync(encryptedContent);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptEmptyEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(string.Empty);
            string decryptedContent = await pgpDecrypt.DecryptAsync(encryptedContent);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().BeEmpty();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetCompressionAlgorithimTags))]
        public async Task DecryptAsync_DecryptEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptAsync(encryptedContent);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetHashAlgorithimTags))]
        public async Task DecryptAsync_DecryptEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptAsync(encryptedContent);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetSymmetricAlgorithimTags))]
        public async Task DecryptAsync_DecryptEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptAsync(encryptedContent);

            PgpInspectResult pgpInspectResult = await pgpDecrypt.InspectAsync(encryptedContent);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().NotBeNullOrEmpty();
                decryptedContent.Should().Be(testFactory.Content);
            }

            pgpInspectResult.SymmetricKeyAlgorithm.Should().Be(symmetricKeyAlgorithmTag);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_DecryptEncryptedWithNullSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Null
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.EncryptedContentFileInfo.Create())
                {
                    Func<Task> act = async () => await pgpEncrypt.EncryptAsync(testFactory.Content);
                    await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "unknown symmetric algorithm: Null");
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_DecryptEncryptedWithSaferSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Safer
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Func<Task> act = async () => await pgpEncrypt.EncryptAsync(testFactory.Content);
                    await act.Should().ThrowAsync<SecurityUtilityException>().Where(e => e.Message == "Algorithm SAFER not recognised.");
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptEncryptedWithMultipleKeys_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encrypted = await pgpEncrypt.EncryptAsync(testFactory.Content);
            string decrypted = await pgpDecrypt.DecryptAsync(encrypted);
            string decrypted2 = await pgpDecrypt.DecryptAsync(encrypted);

            // Assert
            using (new AssertionScope())
            {
                encrypted.Should().NotBeNullOrEmpty();
                decrypted.Should().NotBeNullOrEmpty();
                decrypted2.Should().NotBeNullOrEmpty();
                decrypted.Should().Be(testFactory.Content);
                decrypted2.Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptSignedAndEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKey, testFactory2.PrivateKey, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptionAndSigningKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedAndSigned = await pgpEncryptAndSign.EncryptAndSignAsync(testFactory.Content);
            string decrypted = await pgpDecrypt.DecryptAsync(encryptedAndSigned);

            // Assert
            using (new AssertionScope())
            {
                encryptedAndSigned.Should().NotBeNullOrEmpty();
                decrypted.Should().NotBeNullOrEmpty();
                decrypted.Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptUnencryptedMessage_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Func<Task> act = async () => await pgpDecrypt.DecryptAsync(testFactory.Content);
                    await act.Should().ThrowAsync<ArgumentException>().Where(e => e.Message.StartsWith("Failed to detect encrypted content format."));
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encrypted = await pgpEncrypt.EncryptAsync(testFactory.Content);

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Func<Task> act = async () => await pgpDecrypt.DecryptAsync(encrypted);
                    await act.Should().ThrowAsync<ArgumentException>().Where(e => e.Message == "Secret key for message not found.");
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAndVerifyAsync_DecryptSignedAndEncryptedMessage_ShouldDecryptAndVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            await encryptTestFactory.ArrangeAsync(keyType, FileType.Known);
            await signTestFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKey, signTestFactory.PrivateKey, signTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKey, encryptTestFactory.PrivateKey, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            string encryptedAndSigned = await pgpEncryptAndSign.EncryptAndSignAsync(encryptTestFactory.Content);
            string decryptedAndVerified = await pgpDecryptAndVerify.DecryptAndVerifyAsync(encryptedAndSigned);

            // Assert
            using (new AssertionScope())
            {
                encryptedAndSigned.Should().NotBeNullOrEmpty();
                decryptedAndVerified.Should().NotBeNullOrEmpty();
                decryptedAndVerified.Should().Be(encryptTestFactory.Content);
            }

            // Teardown
            encryptTestFactory.Teardown();
            signTestFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAndVerifyAsync_DecryptSignedAndEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            await encryptTestFactory.ArrangeAsync(keyType, FileType.Known);
            await signTestFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKey, encryptTestFactory.PrivateKey, encryptTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKey, encryptTestFactory.PrivateKey, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            string encryptedAndSigned = await pgpEncryptAndSign.EncryptAndSignAsync(encryptTestFactory.Content);

            // Assert
            using (new AssertionScope())
            {
                encryptedAndSigned.Should().NotBeNullOrEmpty();
                Func<Task> act = async () => await pgpDecryptAndVerify.DecryptAndVerifyAsync(encryptedAndSigned);
                await act.Should().ThrowAsync<PgpException>().Where(e => e.Message == "Failed to verify file.");
            }

            // Teardown
            encryptTestFactory.Teardown();
            signTestFactory.Teardown();
        }
    }
}
