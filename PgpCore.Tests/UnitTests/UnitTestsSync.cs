using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Xunit;

namespace PgpCore.Tests
{
    public class UnitTestsSync
    {
        [Fact]
        public void GenerateKey_CreatePublicPrivateKeyFiles()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.PublicKeyFilePath));
            Assert.True(File.Exists(testFactory.PrivateKeyFilePath));

            // Cleanup
            testFactory.Teardown();
        }

        #region File - Path
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptFile_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void EncryptFile_CreateEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignFile_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignFile_CreateClearSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignFile_CreateClearSignedFileAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);

            // Assert
            Assert.True(pgp.VerifyClearFile(testFactory.SignedContentFilePath, testFactory.PublicKeyFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignFile_CreateClearSignedFileAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);
            EncryptionKeys encryptionKeysSign = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys encryptionKeysVerify = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(encryptionKeysSign);
            PGP pgpVerify = new PGP(encryptionKeysVerify);

            // Act
            pgpSign.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);

            // Assert
            Assert.False(pgpVerify.VerifyClearFile(testFactory.SignedContentFilePath));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignFile_CreateClearSignedFileWithBadContentAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);
            string fileContent = File.ReadAllText(testFactory.SignedContentFilePath);
            fileContent = fileContent.Replace("fox", "rabbit");
            File.WriteAllText(testFactory.SignedContentFilePath, fileContent);

            // Assert
            Assert.False(pgp.VerifyClearFile(testFactory.SignedContentFilePath, testFactory.PublicKeyFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFile_CreateEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileAndSign_CreateEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileAndSign_CreateEncryptedAndSignedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void DecryptFile_DecryptEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            pgpEncrypt.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        //[Theory]
        //[InlineData(KeyType.Generated, FileType.GeneratedLarge)]
        //public void DecryptLargeFile_DecryptEncryptedFile(KeyType keyType, FileType fileType)
        //{
        //    // Arrange
        //    Arrange(keyType, fileType);
        //    PGP pgp = new PGP(encryptionKeys);

        //    // Act
        //    pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);
        //    pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

        //    // Assert
        //    Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
        //    Assert.True(File.Exists(testFactory.DecryptedContentFilePath));

        //    // Teardown
        //    Teardown();
        //}

        [Theory]
        [InlineData(KeyType.Generated, FileType.GeneratedMedium)]
        public void Decrypt300MbFile_DecryptEncryptedFileWithMemoryUsageLessThan50Mb(KeyType keyType, FileType fileType)
        {
            // Arrange
            long memoryCap = 50 * 1024 * 1024;
            long startPeakWorkingSet = Process.GetCurrentProcess().PeakWorkingSet64;

            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, fileType);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            
            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            long encryptPeakWorkingSet = Process.GetCurrentProcess().PeakWorkingSet64;
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);
            long decryptPeakWorkingSet = Process.GetCurrentProcess().PeakWorkingSet64;

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True((encryptPeakWorkingSet - startPeakWorkingSet) < memoryCap, "Encryption used more memory than expected");
            Assert.True((decryptPeakWorkingSet - encryptPeakWorkingSet) < memoryCap, "Decryption used more memory than expected");

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptEncryptedFileWithMultipleKeys(KeyType keyType)
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
            pgpEncrypt.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgpEncrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory2.DecryptedContentFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, armor: false);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);

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
        public void DecryptFile_DecryptSignedAndEncryptedFileWithMultipleKeys(KeyType keyType)
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
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgpEncrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFilePath, testFactory2.DecryptedContentFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptUnsignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            var ex = Assert.Throws<PgpException>( () => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath));

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptCompressedUnsignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            var ex = Assert.Throws<PgpException>( () => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath));

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            var ex = Assert.Throws<PgpException>( () => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath));

            // Assert
            Assert.Equal("Failed to verify file.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);

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
        public void DecryptFileAndVerify_DecryptSignedAndEncryptedAndCompressedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);

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
        public void DecryptFileAndVerify_DecryptSignedAndEncryptedFileDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath);

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
        public void Verify_VerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            bool verified = pgpDecrypt.VerifyFile(testFactory.EncryptedContentFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifySignedFileWithBadContent(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            string[] fileLines = File.ReadAllLines(testFactory.EncryptedContentFilePath);
            fileLines[3] = fileLines[3].Substring(0, fileLines[3].Length - 1 - 1) + "x";
            File.WriteAllLines(testFactory.EncryptedContentFilePath, fileLines);
            Action action = () => pgp.VerifyFile(testFactory.EncryptedContentFilePath);

            // Assert
            var ex = Assert.Throws<IOException>(action);
            Assert.Equal("invalid armor", ex.Message);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);
            bool verified = pgp.VerifyFile(testFactory.SignedContentFilePath);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.SignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath);
            bool verified = pgpDecrypt.VerifyFile(testFactory.SignedContentFilePath);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetFileRecipient(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            PgpPublicKey pgpPublicKey = Utilities.ReadPublicKey(testFactory.PublicKeyFileInfo);
            IEnumerable<long> recipients = pgp.GetFileRecipients(testFactory.EncryptedContentFilePath);

            // Assert
            Assert.Equal(pgpPublicKey.KeyId, recipients.FirstOrDefault());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetFileRecipients(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath);
            List<PgpPublicKey> pgpPublicKeys = keys.Select(x => Utilities.ReadPublicKey(x)).ToList();
            IEnumerable<long> recipients = pgp.GetFileRecipients(testFactory.EncryptedContentFilePath);

            // Assert
            Assert.All(recipients, recipient => Assert.Contains(pgpPublicKeys, x => recipient == x.KeyId));

            // Teardown
            testFactory.Teardown();
        }
        #endregion File - Path

        #region File - FileInfo
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptFileInfo_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void EncryptFileInfo_CreateEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignFileInfo_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignFileInfo_CreateClearSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.ClearSignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndVerifyFileInfo_CreateClearSignedFileAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.ClearSignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(pgp.VerifyClearFile(testFactory.SignedContentFileInfo, testFactory.PublicKeyFileInfo));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndDoNotVerifyFileInfo_CreateClearSignedFileAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);
            EncryptionKeys encryptionKeysSign = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys encryptionKeysVerify = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(encryptionKeysSign);
            PGP pgpVerify = new PGP(encryptionKeysVerify);

            // Act
            pgpSign.ClearSignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.False(pgpVerify.VerifyClearFile(testFactory.SignedContentFileInfo));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileInfo_CreateEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileAndSignInfo_CreateEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileAndSignInfo_CreateEncryptedAndSignedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileInfo_DecryptEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void DecryptFileInfo_DecryptEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            pgpEncrypt.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        ////[Theory]
        ////[InlineData(KeyType.Generated, FileType.GeneratedLarge)]
        ////public void DecryptLargeFileInfo_DecryptEncryptedFile(KeyType keyType, FileType fileType)
        ////{
        ////    // Arrange
        ////    Arrange(keyType, fileType);
        ////    PGP pgp = new PGP(encryptionKeys);

        ////    // Act
        ////    pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);
        ////    pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

        ////    // Assert
        ////    Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
        ////    Assert.True(File.Exists(testFactory.DecryptedContentFilePath));

        ////    // Teardown
        ////    Teardown();
        ////}

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileInfo_DecryptEncryptedFileWithMultipleKeys(KeyType keyType)
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
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpEncrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileInfo_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgp.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public void DecryptFileInfo_DecryptSignedAndEncryptedFileWithMultipleKeys(KeyType keyType)
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
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpEncrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileInfoAndVerify_DecryptUnsignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<PgpException>(() => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo,
               testFactory.DecryptedContentFileInfo));

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }


        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileInfoAndVerify_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<PgpException>(() => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo,
               testFactory.DecryptedContentFileInfo));

            // Assert
            Assert.Equal("Failed to verify file.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileInfoAndVerify_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public void DecryptFileInfoAndVerify_DecryptSignedAndEncryptedAndCompressedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public void DecryptFileInfoAndVerify_DecryptSignedAndEncryptedFileDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public void VerifyFileInfo_VerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFileInfo_DoNotVerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAndSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            bool verified = pgpDecrypt.VerifyFile(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFileInfo_VerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = pgp.VerifyFile(testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFileInfo_DoNotVerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = pgpDecrypt.VerifyFile(testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        #endregion File - FileInfo

        #region Stream
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStream_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignStream_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.SignStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStream_CreateEncryptedStreamWithMultipleKeys(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStreamAndSign_CreateEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStreamAndSign_CreateEncryptedAndSignedStreamWithMultipleKeys(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
                pgpDecrypt.DecryptStream(inputFileStream, outputFileStream);

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
        public void DecryptStream_DecryptEncryptedStreamWithMultipleKeys(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
                pgpEncrypt.DecryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
                pgpDecrypt.DecryptStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptSignedAndEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
                pgp.DecryptStream(inputFileStream, outputFileStream);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptSignedAndEncryptedStreamWithMultipleKeys(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
                pgpEncrypt.DecryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
                pgpDecrypt.DecryptStream(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = pgpEncrypt.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = pgp.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyStream);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgpEncrypt.EncryptStreamAndSign(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = pgpDecrypt.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
                pgp.SignStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = pgp.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyStream, testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            bool verified = true;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
                pgpEncrypt.SignStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = pgpDecrypt.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStreamRecipient(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStream(inputFileStream, outputFileStream);

            PgpPublicKey pgpPublicKey = Utilities.ReadPublicKey(testFactory.PublicKeyStream);
            IEnumerable<long> recipients = pgp.GetStreamRecipients(testFactory.EncryptedContentStream);

            // Assert
            Assert.Equal(pgpPublicKey.KeyId, recipients.FirstOrDefault());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStreamRecipients(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
                pgp.EncryptStream(inputFileStream, outputFileStream);

            keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            List<PgpPublicKey> pgpPublicKeys = keys.Select(x => Utilities.ReadPublicKey(x)).ToList();
            IEnumerable<long> recipients = pgp.GetStreamRecipients(testFactory.EncryptedContentStream);

            // Assert
            Assert.All(recipients, recipient => Assert.Contains(pgpPublicKeys, x => recipient == x.KeyId));

            // Teardown
            testFactory.Teardown();
        }
        #endregion Stream

        #region Armor
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptArmoredString_CreateEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void EncryptArmoredString_CreateEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignArmoredString_CreateSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignArmoredString_CreateClearSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = pgp.ClearSignArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(clearSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndVerifyArmoredString_CreateClearSignedStringAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = pgp.ClearSignArmoredString(testFactory.Content);

            // Assert
            Assert.True(pgp.VerifyClearArmoredString(clearSignedContent));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndDoNotVerifyArmoredString_CreateClearSignedStringAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string clearSignedContent = pgpEncrypt.ClearSignArmoredString(testFactory.Content);

            // Assert
            Assert.False(pgpDecrypt.VerifyClearArmoredString(clearSignedContent));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptArmoredString_CreateEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptArmoredStringAndSign_CreateEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedAndSignedContent = pgp.EncryptArmoredStringAndSign(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptArmoredStringAndSign_CreateEncryptedAndSignedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);
            
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedAndSignedContent = pgp.EncryptArmoredStringAndSign(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void DecryptArmoredString_DecryptEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                HashAlgorithmTag = hashAlgorithmTag
            };

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptEncryptedStringWithMultipleKeys(KeyType keyType)
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
            string encryptedContent = pgpEncrypt.EncryptArmoredString(testFactory.Content);
            string decryptedContent1 = pgpEncrypt.DecryptArmoredString(encryptedContent);
            string decryptedContent2 = pgpDecrypt.DecryptArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent1);
            Assert.NotNull(decryptedContent2);
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAndSign(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptSignedAndEncryptedStringWithMultipleKeys(KeyType keyType)
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
            string encryptedAndSignedContent = pgpEncrypt.EncryptArmoredStringAndSign(testFactory.Content);
            string decryptedContent1 = pgpEncrypt.DecryptArmoredString(encryptedAndSignedContent);
            string decryptedContent2 = pgpDecrypt.DecryptArmoredString(encryptedAndSignedContent);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);
            Assert.NotNull(decryptedContent1);
            Assert.NotNull(decryptedContent2);
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptUnsignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string decryptedContent = null;
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            var ex = Assert.Throws<PgpException>( () => decryptedContent = pgp.DecryptArmoredStringAndVerify(encryptedContent));

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.NotNull(encryptedContent);
            Assert.Null(decryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory.PrivateKey, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string decryptedContent = null;
            string encryptedContent = pgpEncrypt.EncryptArmoredStringAndSign(testFactory.Content);
            var ex = Assert.Throws<PgpException>( () => decryptedContent = pgpDecrypt.DecryptArmoredStringAndVerify(encryptedContent));

            // Assert
            Assert.Equal("Failed to verify file.", ex.Message);
            Assert.NotNull(encryptedContent);
            Assert.Null(decryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAndSign(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredStringAndVerify(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptSignedAndEncryptedAndCompressedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAndSign(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredStringAndVerify(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptSignedAndEncryptedStringDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.EncryptArmoredStringAndSign(testFactory.Content);
            string decryptedContent = pgpDecrypt.DecryptArmoredStringAndVerify(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAndSign(testFactory.Content);
            bool verified = pgp.VerifyArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.EncryptArmoredStringAndSign(testFactory.Content);
            bool verified = pgpDecrypt.VerifyArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content);
            bool verified = pgp.VerifyArmoredString(signedContent);

            // Assert
            Assert.NotNull(signedContent);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string signedContent = pgpEncrypt.SignArmoredString(testFactory.Content);
            bool verified = pgpDecrypt.VerifyArmoredString(signedContent);

            // Assert
            Assert.NotNull(signedContent);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStringRecipient(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.ContentFilePath);
            PgpPublicKey pgpPublicKey = Utilities.ReadPublicKey(testFactory.PublicKey);
            IEnumerable<long> recipients = pgp.GetArmoredStringRecipients(encryptedContent);

            // Assert
            Assert.Equal(pgpPublicKey.KeyId, recipients.FirstOrDefault());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStringRecipients(KeyType keyType)
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

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.ContentFilePath);
            List<PgpPublicKey> pgpPublicKeys = keys.Select(x => Utilities.ReadPublicKey(x)).ToList();
            IEnumerable<long> recipients = pgp.GetArmoredStringRecipients(encryptedContent);

            // Assert
            Assert.All(recipients, recipient => Assert.Contains(pgpPublicKeys, x => recipient == x.KeyId));

            // Teardown
            testFactory.Teardown();
        }
        #endregion Armor

        public static IEnumerable<object[]> KeyTypeValues()
        {
            foreach (var keyType in Enum.GetValues(typeof(KeyType)))
            {
                yield return new object[] { keyType };
            }
        }

        public static IEnumerable<object[]> HashAlgorithmTagValues()
        {
            foreach (var hashAlgorithmTag in Enum.GetValues(typeof(HashAlgorithmTag)))
            {
                yield return new object[] { hashAlgorithmTag };
            }
        }
    }
}
