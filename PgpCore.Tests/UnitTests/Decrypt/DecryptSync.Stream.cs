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
    public class DecryptSync_Stream : TestBase
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(new MemoryStream(), outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, armor: false);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, armor: false);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, armor: false);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(testFactory.EncryptedContentStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, armor: false);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(testFactory.EncryptedContentStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Null
            };

            // Act

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.EncryptedContentFileInfo.Create())
                {
                    Action act = () => pgpEncrypt.Encrypt(testFactory.ContentStream, outputStream);
                    act.Should().Throw<PgpException>().Where(e => e.Message == "unknown symmetric algorithm: Null");
                }
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
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
                    Action act = () => pgpEncrypt.Encrypt(testFactory.ContentStream, outputStream);
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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptEncryptedWithMultipleKeys_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<Stream> keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory2.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory2.PrivateKeyStream, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncryptAndSign = new PGP(encryptionAndSigningKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncryptAndSign.EncryptAndSign(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpDecrypt = new PGP(decryptionKeys);
            File.WriteAllText(testFactory.ContentFileInfo.FullName, testFactory.Content);

            // Act

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Action act = () => pgpDecrypt.Decrypt(testFactory.ContentStream, outputStream);
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
        [InlineData(KeyType.Symmetric)]
        public void Decrypt_DecryptEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputStream);

            // Assert
            using (new AssertionScope())
            {
                using (Stream outputStream = testFactory.DecryptedContentFileInfo.Create())
                {
                    Action act = () => pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputStream);
                    act.Should().Throw<ArgumentException>().Where(e => e.Message == "Decryption key for message not found.");
                }
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

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyStream, signTestFactory.PrivateKeyStream, signTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyStream, encryptTestFactory.PrivateKeyStream, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            using (Stream outputFileStream = encryptTestFactory.EncryptedContentFileInfo.Create())
                pgpEncryptAndSign.EncryptAndSign(encryptTestFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = signTestFactory.DecryptedContentFileInfo.Create())
                pgpDecryptAndVerify.DecryptAndVerify(encryptTestFactory.EncryptedContentStream, outputFileStream);

            // Assert
            using (new AssertionScope())
            {
                encryptTestFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                signTestFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(signTestFactory.DecryptedContentFileInfo.FullName).Should().Be(encryptTestFactory.Content);
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

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyStream, encryptTestFactory.PrivateKeyStream, encryptTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyStream, encryptTestFactory.PrivateKeyStream, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            using (Stream outputFileStream = encryptTestFactory.EncryptedContentFileInfo.Create())
                pgpEncryptAndSign.EncryptAndSign(encryptTestFactory.ContentStream, outputFileStream);

            // Assert
            using (new AssertionScope())
            {
                using (Stream inputStream = encryptTestFactory.EncryptedContentFileInfo.OpenRead())
                using (Stream outputStream = signTestFactory.DecryptedContentFileInfo.Create())
                {
                    Action act = () => pgpDecryptAndVerify.DecryptAndVerify(inputStream, outputStream);
                    act.Should().Throw<PgpException>().Where(e => e.Message == "Failed to verify file.");
                }

                encryptTestFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            encryptionKeys.SymmetricKey = testFactory.SymmetricKey;
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            decryptionKeys.SymmetricKey = testFactory.SymmetricKey;
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.Decrypt(testFactory.EncryptedContentStream, outputFileStream);

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

        // Regression test for https://github.com/mattosaurus/PgpCore - DecryptAndVerify only checked the
        // first signature in a multi-signature message, so verification succeeded or failed depending on
        // signing order. It should succeed whenever ANY message signature was made by one of the supplied
        // verification keys, regardless of position.
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

            // Only one of the two signers' public keys is supplied for verification.
            TestFactory verifySignerTestFactory = verifyWithSignerIndex == 0
                ? firstSignerTestFactory
                : secondSignerTestFactory;
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(
                verifySignerTestFactory.PublicKeyStream,
                recipientTestFactory.PrivateKeyStream,
                recipientTestFactory.Password);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            string decrypted;
            using (Stream inputStream = new MemoryStream(message))
            using (Stream outputStream = new MemoryStream())
            {
                pgpDecryptAndVerify.DecryptAndVerify(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                using (StreamReader reader = new StreamReader(outputStream))
                    decrypted = reader.ReadToEnd();
            }

            // Assert
            decrypted.Should().Be(recipientTestFactory.Content);

            // Teardown
            recipientTestFactory.Teardown();
            firstSignerTestFactory.Teardown();
            secondSignerTestFactory.Teardown();
        }
    }
}
