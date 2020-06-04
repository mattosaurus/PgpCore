using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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

        #region File
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptFile_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
            PGP pgp = new PGP();
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
            PGP pgp = new PGP();

            // Act
            pgp.SignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

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
            PGP pgp = new PGP();

            // Act
            pgp.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndVerifyFile_CreateClearSignedFileAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            pgp.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(pgp.VerifyClearFile(testFactory.SignedContentFilePath, testFactory.PublicKeyFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndDoNotVerifyFile_CreateClearSignedFileAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);
            PGP pgp = new PGP();

            // Act
            pgp.ClearSignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.False(pgp.VerifyClearFile(testFactory.SignedContentFilePath, testFactory2.PublicKeyFilePath));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
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

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys);

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
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

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

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys, testFactory.PrivateKeyFilePath, testFactory.Password);

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
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

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
            PGP pgp = new PGP();
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        //[Theory]
        //[InlineData(KeyType.Generated, FileType.GeneratedLarge)]
        //public void DecryptLargeFile_DecryptEncryptedFile(KeyType keyType, FileType fileType)
        //{
        //    // Arrange
        //    Arrange(keyType, fileType);
        //    PGP pgp = new PGP();

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

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory2.DecryptedContentFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password);
            string decryptedContent1 = File.ReadAllText(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = File.ReadAllText(testFactory2.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.True(File.Exists(testFactory2.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

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
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password, armor: false);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

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

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys, testFactory.PrivateKeyFilePath, testFactory.Password);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            pgp.DecryptFile(testFactory.EncryptedContentFilePath, testFactory2.DecryptedContentFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password);
            string decryptedContent1 = File.ReadAllText(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = File.ReadAllText(testFactory2.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.True(File.Exists(testFactory2.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

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
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            pgp.EncryptFile(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);
            var ex = Assert.Throws<PgpException>(() => pgp.DecryptFileAndVerify(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password));
           
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(string.Empty, decryptedContent.Trim());

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

            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            var ex = Assert.Throws<PgpException>(() => pgp.DecryptFileAndVerify(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath, testFactory2.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password));
           
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.Equal("Failed to verify file.", ex.Message);
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(string.Empty, decryptedContent.Trim());

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
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

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

            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password);
            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

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
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
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

            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.False(verified);

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
            PGP pgp = new PGP();

            // Act
            pgp.SignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = pgp.VerifyFile(testFactory.SignedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));
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

            PGP pgp = new PGP();

            // Act
            pgp.SignFile(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = pgp.VerifyFile(testFactory.SignedContentFilePath, testFactory2.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        #endregion File

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
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

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
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.SignStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

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

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStream(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

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
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

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

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 }, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

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
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

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

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStream(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory2.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, testFactory2.Password);

            string decryptedContent1 = File.ReadAllText(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = File.ReadAllText(testFactory2.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.True(File.Exists(testFactory2.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

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
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            string decryptedContent = File.ReadAllText(testFactory.DecryptedContentFilePath);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());
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

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStream(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory2.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, testFactory2.Password);

            string decryptedContent1 = File.ReadAllText(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = File.ReadAllText(testFactory2.DecryptedContentFilePath);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.True(File.Exists(testFactory2.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());
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
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
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

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
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
            PGP pgp = new PGP();
            bool verified = false;

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.SignStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.SignedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                verified = pgp.VerifyStream(inputFileStream, publicKeyStream);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));
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

            PGP pgp = new PGP();
            bool verified = false;

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                pgp.SignStream(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.SignedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                verified = pgp.VerifyStream(inputFileStream, publicKeyStream);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        #endregion Stream

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
