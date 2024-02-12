using FluentAssertions.Execution;
using FluentAssertions;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using System.IO;

namespace PgpCore.Tests.UnitTests.Verify
{
    public class VerifyAsync_Stream : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyAsync_VerifySignedMessage_ShouldVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream);
            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyAsync_VerifyAndReadSignedMessage_ShouldVerifyAndReadMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream);
            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyAsync_VerifySignedMessageWithWrongKey_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();

            await testFactory1.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory1.PrivateKeyStream, testFactory1.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory2.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory1.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory1.ContentStream, outputFileStream);
            bool verified = await pgpVerify.VerifyAsync(testFactory1.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeFalse();
            }

            // Teardown
            testFactory1.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyClearAsync_VerifyClearSignedMessage_ShouldVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.ClearSignAsync(testFactory.ContentStream, outputFileStream);
            bool verified = await pgpVerify.VerifyClearAsync(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyClearAsync_VerifyAndReadClearSignedMessage_ShouldVerifyAndReadMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.ClearSignAsync(testFactory.ContentStream, outputFileStream);
            bool verified = await pgpVerify.VerifyClearAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                string result = File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName);
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyClearAsync_VerifyClearSignedMessageWithWrongKey_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();

            await testFactory1.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory1.PrivateKeyStream, testFactory1.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory2.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory1.EncryptedContentFileInfo.Create())
                await pgpSign.ClearSignAsync(testFactory1.ContentStream, outputFileStream);
            bool verified = await pgpVerify.VerifyClearAsync(testFactory1.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeFalse();
            }

            // Teardown
            testFactory1.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyClearAsync_VerifyClearSignedModifiedMessage_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();

            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.ClearSignAsync(testFactory.ContentStream, outputFileStream);

            string encryptedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);
            string modifiedContent = new string(testFactory.Content.Reverse().ToArray());
            File.WriteAllText(testFactory.EncryptedContentFileInfo.FullName, encryptedContent.Replace(testFactory.Content, modifiedContent));

            bool verified = await pgpVerify.VerifyClearAsync(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeFalse();
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
