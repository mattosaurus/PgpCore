using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Helpers;
using System.Linq;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// Signatures may be made by any key in a ring (e.g. a signing subkey), so the
    /// verification pool must contain every key, not just the "best" one per ring (#300).
    /// </summary>
    public class VerificationKeyPool : TestBase
    {
        [Fact]
        public void VerificationKeys_GpgKeyWithSubkeys_ContainsAllKeysInRing()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.KnownGpg, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            int totalKeysInRings = encryptionKeys.PublicKeyRings
                .SelectMany(ring => ring.PgpPublicKeyRing.GetPublicKeys().Cast<PgpPublicKey>())
                .Count();

            // Act
            PgpPublicKey[] verificationKeys = encryptionKeys.VerificationKeys.ToArray();

            // Assert
            using (new AssertionScope())
            {
                totalKeysInRings.Should().BeGreaterThan(1, "the gpg test key is expected to have subkeys");
                verificationKeys.Should().HaveCount(totalKeysInRings);
                verificationKeys.Select(k => k.KeyId).Should().OnlyHaveUniqueItems();
            }

            // Teardown
            testFactory.Teardown();
        }

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
