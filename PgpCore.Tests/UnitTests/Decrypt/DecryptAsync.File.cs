using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    public class DecryptAsync_File : TestBase
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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

        [Fact]
        public async Task DecryptAsync_DecryptLargeEncryptedFile_ShouldDecryptMessage()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.GeneratedLarge);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

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

            // Create empty file
            testFactory.ContentFileInfo.Create().Close();

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptBinaryEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptBinaryEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptBinaryEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            PgpInspectResult pgpInspectResult = await pgpDecrypt.InspectAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptBinaryEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            PgpInspectResult pgpInspectResult = await pgpDecrypt.InspectAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptEncryptedWithNullSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Null
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            var ex = await Assert.ThrowsAsync<PgpException>(async () => await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo));

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
        public async Task DecryptAsync_DecryptEncryptedWithSaferSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Safer
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            var ex = await Assert.ThrowsAsync<SecurityUtilityException>(async () => await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo));

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
        public async Task DecryptAsync_DecryptEncryptedWithMultipleKeys_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpEncrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptSignedAndEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptionAndSigningKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncryptAndSign.EncryptAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAsync_DecryptUnencryptedMessage_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            File.WriteAllText(testFactory.ContentFileInfo.FullName, testFactory.Content);

            // Act
            var ex = await Assert.ThrowsAsync<ArgumentException>(async () => await pgpDecrypt.DecryptAsync(testFactory.ContentFileInfo, testFactory.DecryptedContentFileInfo));

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
        public async Task DecryptAsync_DecryptEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = await Assert.ThrowsAsync<ArgumentException>(async () => await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo));

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
        public async Task DecryptAsync_DecryptEncryptedMessageWithoutPassword_ShouldDecryptMessage()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            string password = string.Empty;

            PGP pgpKeys = new PGP();
            await pgpKeys.GenerateKeyAsync(
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
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAndVerifyAsync_DecryptSignedAndEncryptedMessage_ShouldDecryptAndVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            await encryptTestFactory.ArrangeAsync(keyType, FileType.Known);
            await signTestFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyFileInfo, signTestFactory.PrivateKeyFileInfo, signTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            await pgpEncryptAndSign.EncryptAndSignAsync(encryptTestFactory.ContentFileInfo, encryptTestFactory.EncryptedContentFileInfo);
            await pgpDecryptAndVerify.DecryptAndVerifyAsync(encryptTestFactory.EncryptedContentFileInfo, encryptTestFactory.DecryptedContentFileInfo);

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
        public async Task DecryptAndVerifyAsync_DecryptSignedAndEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            await encryptTestFactory.ArrangeAsync(keyType, FileType.Known);
            await signTestFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            await pgpEncryptAndSign.EncryptAndSignAsync(encryptTestFactory.ContentFileInfo, encryptTestFactory.EncryptedContentFileInfo);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => await pgpDecryptAndVerify.DecryptAndVerifyAsync(encryptTestFactory.EncryptedContentFileInfo, encryptTestFactory.DecryptedContentFileInfo));

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
