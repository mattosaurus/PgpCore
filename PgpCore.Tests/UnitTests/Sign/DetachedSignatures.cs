using FluentAssertions;
using FluentAssertions.Execution;
using PgpCore.Tests.UnitTests.Interop;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Sign
{
    public class DetachedSignatures : TestBase
    {
        #region Round-trip

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignDetached_File_ThenVerifyDetached_ShouldReturnTrue(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            await pgpSign.SignDetachedAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = await pgpVerify.VerifyDetachedAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.SignedContentFileInfo.Exists.Should().BeTrue();
                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignDetached_FileBinary_ThenVerifyDetached_ShouldReturnTrue(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            await pgpSign.SignDetachedAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo, armor: false);
            bool verified = await pgpVerify.VerifyDetachedAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            verified.Should().BeTrue();

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignDetached_Stream_ThenVerifyDetached_ShouldReturnTrue(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            byte[] signature;
            using (Stream inputStream = testFactory.ContentStream)
            using (MemoryStream outputStream = new MemoryStream())
            {
                // Act
                await pgpSign.SignDetachedAsync(inputStream, outputStream);
                signature = outputStream.ToArray();
            }

            bool verified;
            using (Stream inputStream = testFactory.ContentStream)
            using (MemoryStream signatureStream = new MemoryStream(signature))
            {
                verified = await pgpVerify.VerifyDetachedAsync(inputStream, signatureStream);
            }

            // Assert
            using (new AssertionScope())
            {
                signature.Should().NotBeEmpty();
                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignDetached_String_ThenVerifyDetached_ShouldReturnTrue(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signature = await pgpSign.SignDetachedAsync(testFactory.Content);
            bool verified = await pgpVerify.VerifyDetachedAsync(testFactory.Content, signature);

            // Assert
            using (new AssertionScope())
            {
                signature.Should().Contain("BEGIN PGP SIGNATURE");
                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignDetached_StringSync_ThenVerifyDetached_ShouldReturnTrue(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signature = pgpSign.SignDetached(testFactory.Content);
            bool verified = pgpVerify.VerifyDetached(testFactory.Content, signature);

            // Assert
            verified.Should().BeTrue();

            // Teardown
            testFactory.Teardown();
        }

        #endregion Round-trip

        #region Negative

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyDetached_TamperedData_ShouldReturnFalse(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signature = await pgpSign.SignDetachedAsync(testFactory.Content);
            bool verified = await pgpVerify.VerifyDetachedAsync(testFactory.Content + " tampered", signature);

            // Assert
            verified.Should().BeFalse();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task VerifyDetached_WrongKey_ShouldReturnFalse()
        {
            // Arrange - sign with one key, verify with a different key.
            TestFactory signerFactory = new TestFactory();
            TestFactory verifierFactory = new TestFactory();
            await signerFactory.ArrangeAsync(KeyType.Generated, FileType.Known);
            await verifierFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys signingKeys = new EncryptionKeys(signerFactory.PrivateKeyFileInfo, signerFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(verifierFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signature = await pgpSign.SignDetachedAsync(signerFactory.Content);
            bool verified = await pgpVerify.VerifyDetachedAsync(signerFactory.Content, signature);

            // Assert
            verified.Should().BeFalse();

            // Teardown
            signerFactory.Teardown();
            verifierFactory.Teardown();
        }

        #endregion Negative

        #region Interop

        [GpgFact]
        [Trait("Category", "Interop")]
        public void PgpCoreSignDetached_GpgVerify_ShouldReportValidSignature()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                testFactory.Arrange(KeyType.Generated, FileType.Known);
                EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
                PGP pgp = new PGP(signingKeys);

                string sigFilePath = Path.Combine(homeDir, "content.txt.sig");

                // Act - produce a detached signature over the content file.
                pgp.SignDetached(testFactory.ContentFileInfo, new FileInfo(sigFilePath));

                GpgResult importPublic = GpgRunner.Run(homeDir, null,
                    "--import", testFactory.PublicKeyFileInfo.FullName);
                // gpg --verify <sigfile> <datafile> verifies a detached signature.
                GpgResult verify = GpgRunner.Run(homeDir, null,
                    "--verify", sigFilePath, testFactory.ContentFileInfo.FullName);

                // Assert
                importPublic.ExitCode.Should().Be(0, "gpg should import the PgpCore public key: {0}", importPublic.Details);
                verify.ExitCode.Should().Be(0, "gpg should verify the PgpCore detached signature: {0}", verify.Details);
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
                testFactory.Teardown();
            }
        }

        [GpgFact]
        [Trait("Category", "Interop")]
        public void GpgDetachSign_PgpCoreVerifyDetached_ShouldReturnTrue()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                testFactory.Arrange(KeyType.Generated, FileType.Known);

                GpgResult importPublic = GpgRunner.Run(homeDir, null,
                    "--import", testFactory.PublicKeyFileInfo.FullName);
                GpgResult importSecret = GpgRunner.Run(homeDir, testFactory.Password,
                    "--import", testFactory.PrivateKeyFileInfo.FullName);

                string sigFilePath = Path.Combine(homeDir, "content.txt.sig");

                // Act - gpg produces a detached signature, PgpCore verifies it.
                GpgResult sign = GpgRunner.Run(homeDir, testFactory.Password,
                    "--armor",
                    "--output", sigFilePath,
                    "--detach-sign", testFactory.ContentFileInfo.FullName);

                EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
                PGP pgpVerify = new PGP(verificationKeys);
                bool verified = pgpVerify.VerifyDetached(testFactory.ContentFileInfo, new FileInfo(sigFilePath));

                // Assert
                using (new AssertionScope())
                {
                    importPublic.ExitCode.Should().Be(0, "gpg should import the PgpCore public key: {0}", importPublic.Details);
                    importSecret.ExitCode.Should().Be(0, "gpg should import the PgpCore private key: {0}", importSecret.Details);
                    sign.ExitCode.Should().Be(0, "gpg should produce a detached signature: {0}", sign.Details);
                    verified.Should().BeTrue();
                }
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
                testFactory.Teardown();
            }
        }

        #endregion Interop
    }
}
