using FluentAssertions;
using FluentAssertions.Execution;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Inspect
{
    /// <summary>
    /// Inspect should only evaluate the properties it has keys for, rather than requiring a
    /// matching private key just to report outer-packet metadata (#302).
    /// </summary>
    public class InspectWithoutKeys : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task InspectAsync_EncryptedMessageWithoutPrivateKey_ShouldReportOuterProperties(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            string encrypted = await pgpEncrypt.EncryptAsync(testFactory.Content);

            // Inspect with only the public key - no private key supplied
            PGP pgpInspect = new PGP(new EncryptionKeys(testFactory.PublicKey));

            // Act
            var result = await pgpInspect.InspectAsync(encrypted);

            // Assert
            using (new AssertionScope())
            {
                result.IsEncrypted.Should().BeTrue();
                result.IsIntegrityProtected.Should().BeTrue();
                result.IsArmored.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public async Task InspectAsync_EncryptedMessageWithWrongPrivateKey_ShouldReportOuterProperties(KeyType keyType)
        {
            // Arrange - decryption keys belong to a different key pair
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            string encrypted = await pgpEncrypt.EncryptAsync(testFactory.Content);

            PGP pgpInspect = new PGP(new EncryptionKeys(testFactory2.PrivateKey, testFactory2.Password));

            // Act
            var result = await pgpInspect.InspectAsync(encrypted);

            // Assert
            using (new AssertionScope())
            {
                result.IsEncrypted.Should().BeTrue();
                result.IsIntegrityProtected.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }
    }
}
