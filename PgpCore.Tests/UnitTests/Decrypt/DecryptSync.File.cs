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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptEmptyEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            // Create empty file
            testFactory.ContentFileInfo.Create().Close();

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().BeEmpty();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptBinaryEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [MemberData(nameof(GetCompressionAlgorithmTags))]
        public void Decrypt_DecryptEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [MemberData(nameof(GetCompressionAlgorithmTags))]
        public void Decrypt_DecryptBinaryEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [MemberData(nameof(GetHashAlgorithmTags))]
        public void Decrypt_DecryptEncryptedWithSpecifiedHashAlgorithm_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [MemberData(nameof(GetHashAlgorithmTags))]
        public void Decrypt_DecryptBinaryEncryptedWithSpecifiedHashAlgorithm_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [MemberData(nameof(GetSymmetricAlgorithmTags))]
        public void Decrypt_DecryptEncryptedWithSpecifiedSymmetricKeyAlgorithm_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [MemberData(nameof(GetSymmetricAlgorithmTags))]
        public void Decrypt_DecryptBinaryEncryptedWithSpecifiedSymmetricKeyAlgorithm_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        public void Decrypt_DecryptEncryptedWithNullSymmetricKeyAlgorithm_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        public void Decrypt_DecryptEncryptedWithSaferSymmetricKeyAlgorithm_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptSignedAndEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptUnencryptedMessage_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey) { SymmetricKey = testFactory.SymmetricKey };
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
                ex.Message.Should().Be("Decryption key for message not found.");
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
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
        [InlineData(KeyType.Symmetric)]
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

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptWithSymmetricKeySetViaProperty_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            encryptionKeys.SymmetricKey = testFactory.SymmetricKey;
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            decryptionKeys.SymmetricKey = testFactory.SymmetricKey;
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
        public void Decrypt_DecryptWithoutSymmetricKeySet_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
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
                encryptionKeys.SymmetricKey.Should().BeNull();
                decryptionKeys.SymmetricKey.Should().BeNull();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        // Regression test: DecryptAndVerify must succeed whenever ANY signature in a multi-signature message
        // was made by one of the supplied verification keys, regardless of the signature's position.
        [Theory]
        [InlineData(0)] // only the first signer's public key is supplied
        [InlineData(1)] // only the second signer's public key is supplied
        public void DecryptAndVerify_MessageSignedWithMultipleKeysVerifyWithEither_ShouldDecryptAndVerifyMessage(int verifyWithSignerIndex)
        {
            // Arrange
            TestFactory recipientTestFactory = new TestFactory();
            TestFactory firstSignerTestFactory = new TestFactory();
            TestFactory secondSignerTestFactory = new TestFactory();

            recipientTestFactory.Arrange(KeyType.Generated, FileType.Known);
            firstSignerTestFactory.Arrange(KeyType.Generated, FileType.Known);
            secondSignerTestFactory.Arrange(KeyType.Generated, FileType.Known);

            // Message encrypted to the recipient and signed by both signers (as `gpg -r recipient -u s1 -u s2`).
            byte[] message = CreateEncryptedAndDoubleSignedMessage(
                recipientTestFactory.Content,
                recipientTestFactory.PublicKeyStream,
                firstSignerTestFactory.PrivateKeyStream, firstSignerTestFactory.Password,
                secondSignerTestFactory.PrivateKeyStream, secondSignerTestFactory.Password);
            File.WriteAllBytes(recipientTestFactory.EncryptedContentFileInfo.FullName, message);

            // Only one of the two signers' public keys is supplied for verification.
            TestFactory verifySignerTestFactory = verifyWithSignerIndex == 0
                ? firstSignerTestFactory
                : secondSignerTestFactory;
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(
                verifySignerTestFactory.PublicKeyFileInfo,
                recipientTestFactory.PrivateKeyFileInfo,
                recipientTestFactory.Password);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            pgpDecryptAndVerify.DecryptAndVerify(
                recipientTestFactory.EncryptedContentFileInfo, recipientTestFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                recipientTestFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(recipientTestFactory.DecryptedContentFileInfo.FullName).Should().Be(recipientTestFactory.Content);
            }

            // Teardown
            recipientTestFactory.Teardown();
            firstSignerTestFactory.Teardown();
            secondSignerTestFactory.Teardown();
        }
    }
}
