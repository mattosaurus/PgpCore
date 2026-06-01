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
        [InlineData(KeyType.Symmetric)]
        public async Task VerifyAsync_VerifySignedMessage_ShouldVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public async Task VerifyAsync_VerifyAndReadSignedMessage_ShouldVerifyAndReadMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public async Task VerifyAsync_VerifySignedMessageWithWrongKey_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();

            await testFactory1.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory1.PrivateKeyStream, testFactory1.Password) { SymmetricKey = testFactory1.SymmetricKey };
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory2.PublicKeyStream) { SymmetricKey = testFactory2.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public async Task VerifyClearAsync_VerifyClearSignedMessage_ShouldVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
        public async Task VerifyClearAsync_VerifyAndReadClearSignedMessage_ShouldVerifyAndReadMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
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
        [InlineData(KeyType.Symmetric)]
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
        [InlineData(KeyType.Symmetric)]
        public async Task VerifyClearAsync_VerifyClearSignedModifiedMessage_ShouldNotVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();

            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password) { SymmetricKey = testFactory.SymmetricKey };
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream) { SymmetricKey = testFactory.SymmetricKey };
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

        // Regression test: Verify must succeed whenever ANY one-pass signature in a multi-signature message
        // was made by one of the supplied verification keys, regardless of the signature's position.
        [Theory]
        [InlineData(0)] // only the first signer's public key is supplied
        [InlineData(1)] // only the second signer's public key is supplied
        public async Task VerifyAsync_MessageSignedWithMultipleKeysVerifyWithEither_ShouldVerifyMessage(int verifyWithSignerIndex)
        {
            // Arrange
            TestFactory firstSignerTestFactory = new TestFactory();
            TestFactory secondSignerTestFactory = new TestFactory();

            await firstSignerTestFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            await secondSignerTestFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            // Message signed by both signers (as `gpg --sign -u s1 -u s2`).
            byte[] message = CreateDoubleSignedMessage(
                firstSignerTestFactory.Content,
                firstSignerTestFactory.PrivateKeyStream, firstSignerTestFactory.Password,
                secondSignerTestFactory.PrivateKeyStream, secondSignerTestFactory.Password);

            // Only one of the two signers' public keys is supplied for verification.
            TestFactory verifySignerTestFactory = verifyWithSignerIndex == 0
                ? firstSignerTestFactory
                : secondSignerTestFactory;
            EncryptionKeys verificationKeys = new EncryptionKeys(verifySignerTestFactory.PublicKeyStream);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            bool verified;
            using (Stream inputStream = new MemoryStream(message))
                verified = await pgpVerify.VerifyAsync(inputStream);

            // Assert
            verified.Should().BeTrue();

            // Teardown
            firstSignerTestFactory.Teardown();
            secondSignerTestFactory.Teardown();
        }
    }
}
