using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Xunit;

namespace PgpCore.Tests
{
    public class UnitTestsAsync
    {
        [Fact]
        public async Task GenerateKeyAsync_CreatePublicPrivateKeyFiles()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.PublicKeyFilePath));
            Assert.True(File.Exists(testFactory.PrivateKeyFilePath));

            // Cleanup
            testFactory.Teardown();
        }

        #region File
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptFileAsync_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task EncryptFileAsync_CreateEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = new PGP();
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignFileAsync_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.SignFileAsync(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignFileAsync_CreateClearSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.ClearSignFileAsync(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.SignedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndVerifyFileAsync_CreateClearSignedFileAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.ClearSignFileAsync(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(await pgp.VerifyClearFileAsync(testFactory.SignedContentFilePath, testFactory.PublicKeyFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndDoNotVerifyFileAsync_CreateClearSignedFileAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);
            PGP pgp = new PGP();

            // Act
            await pgp.ClearSignFileAsync(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.False(await pgp.VerifyClearFileAsync(testFactory.SignedContentFilePath, testFactory2.PublicKeyFilePath));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptFileAsync_CreateEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys);

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
        public async Task EncryptFileAndSignAsync_CreateEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptFileAndSignAsync_CreateEncryptedAndSignedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys, testFactory.PrivateKeyFilePath, testFactory.Password);

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
        public async Task DecryptFileAsync_DecryptEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task DecryptFileAsync_DecryptEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = new PGP();
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));
            Assert.True(File.Exists(testFactory.DecryptedContentFilePath));
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        //[Theory]
        //[InlineData(KeyType.Generated, FileType.GeneratedLarge)]
        //public async Task DecryptLargeFile_DecryptEncryptedFile(KeyType keyType, FileType fileType)
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
        public async Task DecryptFileAsync_DecryptEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory2.DecryptedContentFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password);
            string decryptedContent1 = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = await File.ReadAllTextAsync(testFactory2.DecryptedContentFilePath);

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
        public async Task DecryptFileAsync_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password, armor: false);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task DecryptFileAsync_DecryptSignedAndEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKeyFilePath,
                testFactory2.PublicKeyFilePath
            };

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, keys, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory2.DecryptedContentFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password);
            string decryptedContent1 = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = await File.ReadAllTextAsync(testFactory2.DecryptedContentFilePath);

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
        public async Task DecryptFileAndVerifyAsync_DecryptUnsignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password));

            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task DecryptFileAndVerifyAsync_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFilePath,
                testFactory.DecryptedContentFilePath, testFactory2.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password));

            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedFileDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory2.PrivateKeyFilePath, testFactory2.Password);
            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task VerifyAsync_VerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
        public async Task VerifyAsync_DoNotVerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);

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
        public async Task VerifyAsync_VerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.SignFileAsync(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = await pgp.VerifyFileAsync(testFactory.SignedContentFilePath, testFactory.PublicKeyFilePath);

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
        public async Task VerifyAsync_DoNotVerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            await pgp.SignFileAsync(testFactory.ContentFilePath, testFactory.SignedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            bool verified = await pgp.VerifyFileAsync(testFactory.SignedContentFilePath, testFactory2.PublicKeyFilePath);

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
        public async Task EncryptStreamAsync_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, publicKeyStream);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignStreamAsync_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAsync_CreateEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAndSignAsync_CreateEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAndSignAsync_CreateEncryptedAndSignedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 }, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(File.Exists(testFactory.EncryptedContentFilePath));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptStreamAsync_DecryptEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, publicKeyStream);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task DecryptStreamAsync_DecryptEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory2.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory2.Password);

            string decryptedContent1 = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = await File.ReadAllTextAsync(testFactory2.DecryptedContentFilePath);

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
        public async Task DecryptStreamAsync_DecryptSignedAndEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            string decryptedContent = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);

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
        public async Task DecryptStreamAsync_DecryptSignedAndEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream2 = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.EncryptedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory2.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory2.Password);

            string decryptedContent1 = await File.ReadAllTextAsync(testFactory.DecryptedContentFilePath);
            string decryptedContent2 = await File.ReadAllTextAsync(testFactory2.DecryptedContentFilePath);

            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
        public async Task VerifyAsync_VerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
        public async Task VerifyAsync_DoNotVerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);

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
        public async Task VerifyAsync_VerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();
            bool verified = false;

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.SignedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream = new FileStream(testFactory.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                verified = await pgp.VerifyStreamAsync(inputFileStream, publicKeyStream);

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
        public async Task VerifyAsync_DoNotVerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();
            bool verified = false;

            // Act
            using (FileStream inputFileStream = new FileStream(testFactory.ContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
            using (Stream privateKeyStream = new FileStream(testFactory.PrivateKeyFilePath, FileMode.Open, FileAccess.Read))
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (FileStream inputFileStream = new FileStream(testFactory.SignedContentFilePath, FileMode.Open, FileAccess.Read))
            using (Stream publicKeyStream = new FileStream(testFactory2.PublicKeyFilePath, FileMode.Open, FileAccess.Read))
                verified = await pgp.VerifyStreamAsync(inputFileStream, publicKeyStream);

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
