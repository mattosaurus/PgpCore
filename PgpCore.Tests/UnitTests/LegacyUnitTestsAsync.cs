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
    public class LegacyUnitTestsAsync
    {
        private static class File
        {
            public static FileStream Create(string path) => System.IO.File.Create(path);
            public static bool Exists(string path) => System.IO.File.Exists(path);
#if NETFRAMEWORK
            public static Task<string> ReadAllTextAsync(string path) => Task.FromResult(System.IO.File.ReadAllText(path));
#else
            public static Task<string> ReadAllTextAsync(string path) => System.IO.File.ReadAllTextAsync(path);
#endif
        }

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
            Assert.True(testFactory.PublicKeyFileInfo.Exists);
            Assert.True(testFactory.PrivateKeyFileInfo.Exists);

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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            Assert.True(testFactory.SignedContentFileInfo.Exists);

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
            Assert.True(testFactory.SignedContentFileInfo.Exists);

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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            string decryptedContent = testFactory.DecryptedContent;

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

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
            string decryptedContent = testFactory.DecryptedContent;

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

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
        //    Assert.True(testFactory.EncryptedContentFileInfo.Exists);
        //    Assert.True(testFactory.DecryptedContentFileInfo.Exists);

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
        public async Task DecryptFileAsync_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password, armor: false);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedAndCompressedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFilePath, testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);
            await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFilePath, testFactory.DecryptedContentFilePath, testFactory.PublicKeyFilePath, testFactory.PrivateKeyFilePath, testFactory.Password);

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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
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
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
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
            Assert.True(testFactory.SignedContentFileInfo.Exists);
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
            Assert.True(testFactory.SignedContentFileInfo.Exists);
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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, publicKeyStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = testFactory.PublicKeyStream)
            using (Stream publicKeyStream2 = testFactory2.PublicKeyStream)
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = testFactory.PublicKeyStream)
            using (Stream publicKeyStream2 = testFactory2.PublicKeyStream)
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 }, privateKeyStream, testFactory.Password);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, publicKeyStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

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
        public async Task DecryptStreamAsync_DecryptEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = testFactory.PublicKeyStream)
            using (Stream publicKeyStream2 = testFactory2.PublicKeyStream)
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
            using (Stream privateKeyStream = testFactory2.PrivateKeyStream)
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory2.Password);

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
        public async Task DecryptStreamAsync_DecryptSignedAndEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

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
        public async Task DecryptStreamAsync_DecryptSignedAndEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream1 = testFactory.PublicKeyStream)
            using (Stream publicKeyStream2 = testFactory2.PublicKeyStream)
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory.DecryptedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = File.Create(testFactory2.DecryptedContentFilePath))
            using (Stream privateKeyStream = testFactory2.PrivateKeyStream)
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory2.Password);


            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
        public async Task VerifyAsync_VerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory.PublicKeyFilePath);

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
        public async Task VerifyAsync_DoNotVerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            PGP pgp = new PGP();

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.EncryptedContentFilePath))
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, testFactory.Password);

            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFilePath, testFactory2.PublicKeyFilePath);

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
        public async Task VerifyAsync_VerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (Stream inputFileStream = testFactory.SignedContentStream)
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
                verified = await pgp.VerifyStreamAsync(inputFileStream, publicKeyStream);

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
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = File.Create(testFactory.SignedContentFilePath))
            using (Stream privateKeyStream = testFactory.PrivateKeyStream)
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, privateKeyStream, testFactory.Password);

            using (Stream inputFileStream = testFactory.SignedContentStream)
            using (Stream publicKeyStream = testFactory2.PublicKeyStream)
                verified = await pgp.VerifyStreamAsync(inputFileStream, publicKeyStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        #endregion Stream

        #region Armor
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptArmoredStringAsync_CreateEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            PGP pgp = new PGP();
            string publicKey = testFactory.PublicKey;

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, publicKey);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task EncryptArmoredStringAsync_CreateEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = new PGP();
            string publicKey = testFactory.PublicKey;
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, publicKey);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignArmoredStringAsync_CreateSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content, privateKey, testFactory.Password);

            // Assert
            Assert.NotNull(signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignArmoredStringAsync_CreateClearSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string clearSignedContent = await pgp.ClearSignArmoredStringAsync(testFactory.Content, privateKey, testFactory.Password);

            // Assert
            Assert.NotNull(clearSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndVerifyArmoredStringAsync_CreateClearSignedStringAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string clearSignedContent = await pgp.ClearSignArmoredStringAsync(testFactory.Content, privateKey, testFactory.Password);

            // Assert
            Assert.True(await pgp.VerifyClearArmoredStringAsync(clearSignedContent, publicKey));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndDoNotVerifyArmoredStringAsync_CreateClearSignedStringAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string privateKey = testFactory.PrivateKey;
            await testFactory2.ArrangeAsync(KeyType.Generated);
            string publicKey = testFactory2.PublicKey;
            
            PGP pgp = new PGP();

            // Act
            string clearSignedContent = await pgp.ClearSignArmoredStringAsync(testFactory.Content, privateKey, testFactory.Password);

            // Assert
            Assert.False(await pgp.VerifyClearArmoredStringAsync(clearSignedContent, publicKey));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptArmoredStringAsync_CreateEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, keys);

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
        public async Task EncryptArmoredStringAndSignAsync_CreateEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string encryptedAndSignedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptArmoredStringAndSignAsync_CreateEncryptedAndSignedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);
            string privateKey = testFactory.PrivateKey;

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            // Act
            string encryptedAndSignedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, keys, privateKey, testFactory.Password);

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
        public async Task DecryptArmoredStringAsync_DecryptEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, publicKey);
            string decryptedContent = await pgp.DecryptArmoredStringAsync(encryptedContent, privateKey, testFactory.Password);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task DecryptArmoredStringAsync_DecryptEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();
            pgp.HashAlgorithmTag = hashAlgorithmTag;

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, publicKey);
            string decryptedContent = await pgp.DecryptArmoredStringAsync(encryptedContent, privateKey, testFactory.Password);

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
        public async Task DecryptArmoredStringAsync_DecryptEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string privateKey = testFactory.PrivateKey;
            string privateKey2 = testFactory2.PrivateKey;

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, keys);
            string decryptedContent1 = await pgp.DecryptArmoredStringAsync(encryptedContent, privateKey, testFactory.Password);
            string decryptedContent2 = await pgp.DecryptArmoredStringAsync(encryptedContent, privateKey2, testFactory2.Password);

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
        public async Task DecryptArmoredStringAsync_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);
            string decryptedContent = await pgp.DecryptArmoredStringAsync(encryptedContent, privateKey, testFactory.Password);

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
        public async Task DecryptArmoredStringAsync_DecryptSignedAndEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string privateKey = testFactory.PrivateKey;
            string privateKey2 = testFactory2.PrivateKey;

            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            // Act
            string encryptedAndSignedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, keys, privateKey, testFactory.Password);
            string decryptedContent1 = await pgp.DecryptArmoredStringAsync(encryptedAndSignedContent, privateKey, testFactory.Password);
            string decryptedContent2 = await pgp.DecryptArmoredStringAsync(encryptedAndSignedContent, privateKey2, testFactory2.Password);

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptUnsignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string publicKey2 = testFactory2.PublicKey;
            string privateKey2 = testFactory2.PrivateKey;

            PGP pgp = new PGP();

            // Act
            string decryptedContent = null;
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, publicKey2);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent,
                publicKey, privateKey2, testFactory2.Password));

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string publicKey2 = testFactory2.PublicKey;
            string privateKey = testFactory.PrivateKey;

            PGP pgp = new PGP();

            // Act
            string decryptedContent = null;
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent,
                publicKey2, privateKey, testFactory.Password));

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);
            string decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent, publicKey, privateKey, testFactory.Password);

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptSignedAndEncryptedAndCompressedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);
            string decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent, publicKey, privateKey, testFactory.Password);

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptSignedAndEncryptedStringDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            string publicKey2 = testFactory2.PublicKey;
            string privateKey2 = testFactory2.PrivateKey;

            PGP pgp = new PGP();

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey2, privateKey, testFactory.Password);
            string decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent, publicKey, privateKey2, testFactory2.Password);

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
        public async Task VerifyAsync_VerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);
            bool verified = await pgp.VerifyArmoredStringAsync(encryptedContent, publicKey);

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
        public async Task VerifyAsync_DoNotVerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            string publicKey2 = testFactory2.PublicKey;

            PGP pgp = new PGP();

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content, publicKey, privateKey, testFactory.Password);
            bool verified = await pgp.VerifyArmoredStringAsync(encryptedContent, publicKey2);

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
        public async Task VerifyAsync_VerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            string publicKey = testFactory.PublicKey;
            string privateKey = testFactory.PrivateKey;
            PGP pgp = new PGP();

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content, privateKey, testFactory.Password);
            bool verified = await pgp.VerifyArmoredStringAsync(signedContent, publicKey);

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
        public async Task VerifyAsync_DoNotVerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            string privateKey = testFactory.PrivateKey;
            string publicKey2 = testFactory2.PublicKey;

            PGP pgp = new PGP();

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content, privateKey, testFactory.Password);
            bool verified = await pgp.VerifyArmoredStringAsync(signedContent, publicKey2);

            // Assert
            Assert.NotNull(signedContent);
            Assert.False(verified);

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
