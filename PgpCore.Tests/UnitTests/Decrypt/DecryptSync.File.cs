using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    public class DecryptSync_File : TestBase
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptBinaryEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetCompressionAlgorithimTags))]
        public void Decrypt_DecryptBinaryEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetHashAlgorithimTags))]
        public void Decrypt_DecryptBinaryEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            pgpInspectResult.SymmetricKeyAlgorithm.Should().Be(symmetricKeyAlgorithmTag);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetSymmetricAlgorithimTags))]
        public void Decrypt_DecryptBinaryEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Null
            };

            // Act
            var ex = Assert.Throws<PgpException>(() => pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<PgpException>();
                ex.Message.Should().Be("unknown symmetric algorithm: Null");
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Safer
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            var ex = Assert.Throws<SecurityUtilityException>(() => pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<SecurityUtilityException>();
                ex.Message.Should().Be("Algorithm SAFER not recognised.");
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

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpEncrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory2.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory2.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
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

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptionAndSigningKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncryptAndSign.EncryptAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
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

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            File.WriteAllText(testFactory.ContentFileInfo.FullName, testFactory.Content);

            // Act
            var ex = Assert.Throws<ArgumentException>(() => pgpDecrypt.Decrypt(testFactory.ContentFileInfo, testFactory.DecryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<ArgumentException>();
                ex.Message.Should().StartWith("Failed to detect encrypted content format.");
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
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<ArgumentException>(() => pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<ArgumentException>();
                ex.Message.Should().Be("Secret key for message not found.");
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Decrypt_DecryptEncryptedMessageWithoutPassword_ShouldDecryptMessage()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            string password = string.Empty;

            PGP pgpKeys = new PGP();
            pgpKeys.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                password
                );

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
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

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyFileInfo, signTestFactory.PrivateKeyFileInfo, signTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            pgpEncryptAndSign.EncryptAndSign(encryptTestFactory.ContentFileInfo, encryptTestFactory.EncryptedContentFileInfo);
            pgpDecryptAndVerify.DecryptAndVerify(encryptTestFactory.EncryptedContentFileInfo, encryptTestFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                encryptTestFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                encryptTestFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(encryptTestFactory.DecryptedContentFileInfo.FullName).Should().Be(encryptTestFactory.Content);
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

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            pgpEncryptAndSign.EncryptAndSign(encryptTestFactory.ContentFileInfo, encryptTestFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<PgpException>(() => pgpDecryptAndVerify.DecryptAndVerify(encryptTestFactory.EncryptedContentFileInfo, encryptTestFactory.DecryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                encryptTestFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                ex.Should().BeAssignableTo<PgpException>();
                ex.Message.Should().Be("Failed to verify file.");
            }

            // Teardown
            encryptTestFactory.Teardown();
            signTestFactory.Teardown();
        }
    }
}
