using FluentAssertions.Execution;
using FluentAssertions;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using System.IO;

namespace PgpCore.Tests.UnitTests.Verify
{
    public class VerifyAsync_String : TestBase
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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.SignAsync(testFactory.Content);
            bool verified = await pgpVerify.VerifyAsync(signedContent);

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
        public async Task VerifyAsync_VerifySignedMessageWithWrongKey_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();

            await testFactory1.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory1.PrivateKeyFileInfo, testFactory1.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.SignAsync(testFactory1.Content);
            bool verified = await pgpVerify.VerifyAsync(signedContent);

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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.ClearSignAsync(testFactory.Content);
            bool verified = await pgpVerify.VerifyClearAsync(signedContent);

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
        public async Task VerifyClearAsync_VerifyClearSignedMessageWithWrongKey_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();

            await testFactory1.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory1.PrivateKeyFileInfo, testFactory1.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.ClearSignAsync(testFactory1.Content);
            bool verified = await pgpVerify.VerifyClearAsync(signedContent);

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
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();

            await testFactory1.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory1.PrivateKeyFileInfo, testFactory1.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.ClearSignAsync(testFactory1.Content);
            string modifiedContent = new string(testFactory1.Content.Reverse().ToArray());
            signedContent.Replace(testFactory1.Content, modifiedContent);

            bool verified = await pgpVerify.VerifyClearAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeFalse();
            }

            // Teardown
            testFactory1.Teardown();
            testFactory2.Teardown();
        }
    }
}
