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
    public class DecryptSync_String : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content);
            string decryptedContent = pgpDecrypt.Decrypt(encryptedContent);

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
        public void Decrypt_DecryptLargeEncryptedMessage_ShouldDecryptMessage()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.GeneratedLarge);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content);
            string decryptedContent = pgpDecrypt.Decrypt(encryptedContent);

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
        public void Decrypt_DecryptEmptyEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(string.Empty);
            string decryptedContent = pgpDecrypt.Decrypt(encryptedContent);

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
        public void Decrypt_DecryptEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content);
            string decryptedContent = pgpDecrypt.Decrypt(encryptedContent);

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
        public void Decrypt_DecryptEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content);
            string decryptedContent = pgpDecrypt.Decrypt(encryptedContent);

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
        public void Decrypt_DecryptEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content);
            string decryptedContent = pgpDecrypt.Decrypt(encryptedContent);

            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(encryptedContent);

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
        public void Decrypt_DecryptEncryptedWithNullSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
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
                    Action act = () => pgpEncrypt.Encrypt(testFactory.Content);
                    act.Should().Throw<PgpException>().Where(e => e.Message == "unknown symmetric algorithm: Null");
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Decrypt_DecryptEncryptedWithSaferSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
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
                    Action act = () => pgpEncrypt.Encrypt(testFactory.Content);
                    act.Should().Throw<SecurityUtilityException>().Where(e => e.Message == "Algorithm SAFER not recognised.");
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptEncryptedWithMultipleKeys_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

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
            string encrypted = pgpEncrypt.Encrypt(testFactory.Content);
            string decrypted = pgpDecrypt.Decrypt(encrypted);
            string decrypted2 = pgpDecrypt.Decrypt(encrypted);

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
        public void Decrypt_DecryptSignedAndEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKey, testFactory2.PrivateKey, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptionAndSigningKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedAndSigned = pgpEncryptAndSign.EncryptAndSign(testFactory.Content);
            string decrypted = pgpDecrypt.Decrypt(encryptedAndSigned);

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
        public void Decrypt_DecryptUnencryptedMessage_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Action act = () => pgpDecrypt.Decrypt(testFactory.Content);
                    act.Should().Throw<ArgumentException>().Where(e => e.Message.StartsWith("Failed to detect encrypted content format."));
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encrypted = pgpEncrypt.Encrypt(testFactory.Content);

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Action act = () => pgpDecrypt.Decrypt(encrypted);
                    act.Should().Throw<ArgumentException>().Where(e => e.Message == "Secret key for message not found.");
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptAndVerify_DecryptSignedAndEncryptedMessage_ShouldDecryptAndVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            encryptTestFactory.Arrange(keyType, FileType.Known);
            signTestFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKey, signTestFactory.PrivateKey, signTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKey, encryptTestFactory.PrivateKey, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            string encryptedAndSigned = pgpEncryptAndSign.EncryptAndSign(encryptTestFactory.Content);
            string decryptedAndVerified = pgpDecryptAndVerify.DecryptAndVerify(encryptedAndSigned);

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
        public void DecryptAndVerify_DecryptSignedAndEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            encryptTestFactory.Arrange(keyType, FileType.Known);
            signTestFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKey, encryptTestFactory.PrivateKey, encryptTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKey, encryptTestFactory.PrivateKey, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            string encryptedAndSigned = pgpEncryptAndSign.EncryptAndSign(encryptTestFactory.Content);

            // Assert
            using (new AssertionScope())
            {
                encryptedAndSigned.Should().NotBeNullOrEmpty();
                Action act = () => pgpDecryptAndVerify.DecryptAndVerify(encryptedAndSigned);
                act.Should().Throw<PgpException>().Where(e => e.Message == "Failed to verify file.");
            }

            // Teardown
            encryptTestFactory.Teardown();
            signTestFactory.Teardown();
        }
    }
}
