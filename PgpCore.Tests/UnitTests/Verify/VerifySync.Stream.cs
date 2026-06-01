using FluentAssertions;
using System.IO;
using Xunit;

namespace PgpCore.Tests.UnitTests.Verify
{
    public class VerifySync_Stream : TestBase
    {
        // Regression test: Verify must succeed whenever ANY one-pass signature in a multi-signature message
        // was made by one of the supplied verification keys, regardless of the signature's position.
        [Theory]
        [InlineData(0)] // only the first signer's public key is supplied
        [InlineData(1)] // only the second signer's public key is supplied
        public void Verify_MessageSignedWithMultipleKeysVerifyWithEither_ShouldVerifyMessage(int verifyWithSignerIndex)
        {
            // Arrange
            TestFactory firstSignerTestFactory = new TestFactory();
            TestFactory secondSignerTestFactory = new TestFactory();

            firstSignerTestFactory.Arrange(KeyType.Generated, FileType.Known);
            secondSignerTestFactory.Arrange(KeyType.Generated, FileType.Known);

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
                verified = pgpVerify.Verify(inputStream);

            // Assert
            verified.Should().BeTrue();

            // Teardown
            firstSignerTestFactory.Teardown();
            secondSignerTestFactory.Teardown();
        }
    }
}
