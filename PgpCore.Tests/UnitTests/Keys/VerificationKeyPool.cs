using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Helpers;
using System.Linq;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// The verification pool includes authenticated signing keys and keeps the primary first.
    /// Binding and signing-subkey coverage lives in KeyRingValidationTests.
    /// </summary>
    public class VerificationKeyPool : TestBase
    {
        [Fact]
        public void VerificationKeys_FirstKeyIsBestVerificationKey()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.KnownGpg, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PgpPublicKeyRing firstRing = encryptionKeys.PublicKeyRings.First().PgpPublicKeyRing;
            PgpPublicKey bestKey = Utilities.FindBestVerificationKey(firstRing);

            // Act
            PgpPublicKey firstVerificationKey = encryptionKeys.VerificationKeys.First();

            // Assert
            firstVerificationKey.KeyId.Should().Be(bestKey.KeyId);

            // Teardown
            testFactory.Teardown();
        }
    }
}
