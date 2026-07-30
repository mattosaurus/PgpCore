using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// A key generated without a passphrase is stored unencrypted, as gpg does. Encrypting the secret
    /// key material with the empty string looks identical to PgpCore but makes other implementations
    /// (gpg, Kleopatra) demand a non-empty passphrase before the key can be used (GitHub issue #308).
    /// </summary>
    public class GenerateKeyPassphrase : TestBase
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task GenerateKeyAsync_WithoutPassphrase_ShouldStoreSecretKeysUnencrypted(string password)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, password, strength: 1024, certainty: 12);

            // Assert - every key in the ring (master and subkey) must be unprotected.
            using (new AssertionScope())
            using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
            {
                PgpSecretKeyRingBundle bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                PgpSecretKey[] secretKeys = bundle.GetKeyRings().Cast<PgpSecretKeyRing>().Single()
                    .GetSecretKeys().Cast<PgpSecretKey>().ToArray();

                secretKeys.Should().HaveCount(2);
                secretKeys.Should().OnlyContain(key => key.KeyEncryptionAlgorithm == SymmetricKeyAlgorithmTag.Null);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task GenerateKeyAsync_WithoutPassphrase_ShouldRoundTripWithEmptyPassphrase()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgpGenerate = new PGP();
            await pgpGenerate.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, password: null, strength: 1024, certainty: 12);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo, string.Empty);
            PGP pgp = new PGP(keys);

            // Act
            string decrypted = await pgp.DecryptAndVerifyAsync(
                await pgp.EncryptAndSignAsync("no passphrase round trip"));

            // Assert
            decrypted.Trim().Should().Be("no passphrase round trip");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task GenerateKeyAsync_WithPassphrase_ShouldStillEncryptSecretKeys()
        {
            // Arrange - guards against the unencrypted-export path leaking into passphrase-protected keys.
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, testFactory.Password, strength: 1024, certainty: 12);

            // Assert
            using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
            {
                PgpSecretKeyRingBundle bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                bundle.GetKeyRings().Cast<PgpSecretKeyRing>().Single()
                    .GetSecretKeys().Cast<PgpSecretKey>()
                    .Should().OnlyContain(key => key.KeyEncryptionAlgorithm == SymmetricKeyAlgorithmTag.Aes256);
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
