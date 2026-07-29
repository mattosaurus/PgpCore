using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// GenerateKey produces a certify/sign master key plus an encryption subkey. Without the subkey the
    /// signature-only algorithms (EdDSA, ECDSA, DSA) generated a key that could not encrypt at all,
    /// failing with "passed in key not an encryption key!" (GitHub issue #285).
    /// </summary>
    public class GenerateKeySubKeys : TestBase
    {
        /// <summary>
        /// Master algorithm, key strength, and the encryption subkey algorithm it should be paired with.
        /// DSA appears twice to cover both parameter generation paths: 1024 bits uses BouncyCastle's legacy
        /// generator, while 2048 uses the FIPS 186-3 generator with a 256 bit subgroup.
        /// </summary>
        public static TheoryData<PublicKeyAlgorithmTag, int, PublicKeyAlgorithmTag> Algorithms =>
            new TheoryData<PublicKeyAlgorithmTag, int, PublicKeyAlgorithmTag>
            {
                { PublicKeyAlgorithmTag.RsaGeneral, 1024, PublicKeyAlgorithmTag.RsaGeneral },
                { PublicKeyAlgorithmTag.EdDsa, 1024, PublicKeyAlgorithmTag.ECDH },
                { PublicKeyAlgorithmTag.ECDsa, 1024, PublicKeyAlgorithmTag.ECDH },
                { PublicKeyAlgorithmTag.Dsa, 1024, PublicKeyAlgorithmTag.RsaGeneral },
                { PublicKeyAlgorithmTag.Dsa, 2048, PublicKeyAlgorithmTag.RsaGeneral },
            };

        /// <summary>Returns the key flags from the first signature on the key that declares any.</summary>
        private static int GetKeyFlags(PgpPublicKey key)
        {
            foreach (PgpSignature signature in key.GetSignatures())
            {
                PgpSignatureSubpacketVector hashedSubPackets = signature.GetHashedSubPackets();
                if (hashedSubPackets != null && hashedSubPackets.GetKeyFlags() != 0)
                    return hashedSubPackets.GetKeyFlags();
            }

            return 0;
        }

        [Theory]
        [MemberData(nameof(Algorithms))]
        public async Task GenerateKeyAsync_ShouldProduceSigningMasterKeyWithEncryptionSubKey(
            PublicKeyAlgorithmTag masterAlgorithm, int strength, PublicKeyAlgorithmTag expectedSubKeyAlgorithm)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = masterAlgorithm };

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, testFactory.Password, strength: strength, certainty: 12);

            // Assert
            using (new AssertionScope())
            using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
            {
                PgpPublicKeyRingBundle bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
                PgpPublicKey[] keys = bundle.GetKeyRings().Cast<PgpPublicKeyRing>().Single()
                    .GetPublicKeys().Cast<PgpPublicKey>().ToArray();

                keys.Should().HaveCount(2);

                PgpPublicKey master = keys.Single(k => k.IsMasterKey);
                master.Algorithm.Should().Be(masterAlgorithm);
                (GetKeyFlags(master) & PgpKeyFlags.CanCertify).Should().NotBe(0);
                (GetKeyFlags(master) & PgpKeyFlags.CanSign).Should().NotBe(0);
                // Encryption is delegated to the subkey, so the master must not claim it.
                (GetKeyFlags(master) & PgpKeyFlags.CanEncryptCommunications).Should().Be(0);
                (GetKeyFlags(master) & PgpKeyFlags.CanEncryptStorage).Should().Be(0);

                PgpPublicKey subKey = keys.Single(k => !k.IsMasterKey);
                subKey.Algorithm.Should().Be(expectedSubKeyAlgorithm);
                subKey.IsEncryptionKey.Should().BeTrue();
                (GetKeyFlags(subKey) & PgpKeyFlags.CanEncryptCommunications).Should().NotBe(0);
                (GetKeyFlags(subKey) & PgpKeyFlags.CanEncryptStorage).Should().NotBe(0);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(Algorithms))]
        public async Task GenerateKeyAsync_GeneratedKeyShouldEncryptSignAndRoundTrip(
            PublicKeyAlgorithmTag masterAlgorithm, int strength, PublicKeyAlgorithmTag expectedSubKeyAlgorithm)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgpGenerate = new PGP { PublicKeyAlgorithm = masterAlgorithm };
            await pgpGenerate.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, testFactory.Password, strength: strength, certainty: 12);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(keys);

            // Act
            const string content = "generated key round trip";
            string encrypted = await pgp.EncryptAndSignAsync(content);
            string decrypted = await pgp.DecryptAndVerifyAsync(encrypted);

            // Assert
            using (new AssertionScope())
            {
                decrypted.Trim().Should().Be(content);
                // The encryption key is the subkey; signing stays with the master.
                keys.EncryptKeys.Should().ContainSingle()
                    .Which.Algorithm.Should().Be(expectedSubKeyAlgorithm);
                keys.SigningSecretKey.PublicKey.Algorithm.Should().Be(masterAlgorithm);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(256)]
        [InlineData(511)]
        public async Task GenerateKeyAsync_DsaBelowMinimumStrength_ShouldThrowArgumentOutOfRange(int strength)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.Dsa };

            // Act
            Func<Task> act = async () => await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo, testFactory.UserName, testFactory.Password,
                strength: strength, certainty: 12);

            // Assert - previously this surfaced as a raw BouncyCastle message (#285)
            await act.Should().ThrowAsync<ArgumentOutOfRangeException>()
                .Where(e => e.Message.Contains("at least"));

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task GenerateKeyAsync_DsaStrengthNotAMultipleOf64_ShouldThrowArgumentOutOfRange()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.Dsa };

            // Act
            Func<Task> act = async () => await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo, testFactory.UserName, testFactory.Password,
                strength: 1000, certainty: 12);

            // Assert
            await act.Should().ThrowAsync<ArgumentOutOfRangeException>()
                .Where(e => e.Message.Contains("multiple of 64"));

            // Teardown
            testFactory.Teardown();
        }

        /// <summary>
        /// Returns the hash algorithm actually used for the master key's self-certification.
        /// </summary>
        private static HashAlgorithmTag GetSelfCertificationHash(FileInfo publicKeyFile)
        {
            using Stream publicKeyStream = publicKeyFile.OpenRead();
            PgpPublicKeyRingBundle bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
            PgpPublicKey master = bundle.GetKeyRings().Cast<PgpPublicKeyRing>().Single()
                .GetPublicKeys().Cast<PgpPublicKey>().Single(k => k.IsMasterKey);
            string userId = master.GetUserIds().Cast<string>().First();
            return master.GetSignaturesForId(userId).Cast<PgpSignature>().First().HashAlgorithm;
        }

        /// <summary>
        /// Digests shorter than the key algorithm requires must be replaced. EdDSA and ECDSA P-256 need 256
        /// bits, and DSA needs at least its subgroup size, so anything shorter produces a self-certification
        /// other implementations may reject - and for MD5 with ECDSA or DSA, BouncyCastle cannot sign at all.
        /// </summary>
        public static TheoryData<PublicKeyAlgorithmTag, int, HashAlgorithmTag> ShortCertificationHashes =>
            new TheoryData<PublicKeyAlgorithmTag, int, HashAlgorithmTag>
            {
                { PublicKeyAlgorithmTag.EdDsa, 1024, HashAlgorithmTag.Sha224 },
                { PublicKeyAlgorithmTag.EdDsa, 1024, HashAlgorithmTag.Sha1 },
                { PublicKeyAlgorithmTag.EdDsa, 1024, HashAlgorithmTag.MD5 },
                { PublicKeyAlgorithmTag.EdDsa, 1024, HashAlgorithmTag.RipeMD160 },
                { PublicKeyAlgorithmTag.ECDsa, 1024, HashAlgorithmTag.Sha224 },
                { PublicKeyAlgorithmTag.ECDsa, 1024, HashAlgorithmTag.Sha1 },
                { PublicKeyAlgorithmTag.ECDsa, 1024, HashAlgorithmTag.MD5 },
                // DSA above the legacy limit uses a 256 bit subgroup, so 224 bits is too short.
                { PublicKeyAlgorithmTag.Dsa, 2048, HashAlgorithmTag.Sha224 },
                { PublicKeyAlgorithmTag.Dsa, 2048, HashAlgorithmTag.Sha1 },
                // A 1024 bit DSA key has a 160 bit subgroup, so only digests below that are replaced.
                { PublicKeyAlgorithmTag.Dsa, 1024, HashAlgorithmTag.MD5 },
                // Reserved and unsupported digests have no usable size and are replaced rather than
                // being allowed to fail during signing.
                { PublicKeyAlgorithmTag.EdDsa, 1024, HashAlgorithmTag.DoubleSha },
            };

        [Theory]
        [MemberData(nameof(ShortCertificationHashes))]
        public async Task GenerateKeyAsync_CertificationHashTooShortForAlgorithm_ShouldUseSha256(
            PublicKeyAlgorithmTag algorithm, int strength, HashAlgorithmTag requestedHash)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = algorithm, HashAlgorithmTag = requestedHash };

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, testFactory.Password, strength: strength, certainty: 12);

            // Assert
            using (new AssertionScope())
            {
                GetSelfCertificationHash(testFactory.PublicKeyFileInfo).Should().Be(HashAlgorithmTag.Sha256);

                // The substitution has to leave a working key behind, not just a well-formed one.
                EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKeyFileInfo,
                    testFactory.PrivateKeyFileInfo, testFactory.Password);
                PGP roundTrip = new PGP(keys);
                string decrypted = await roundTrip.DecryptAndVerifyAsync(
                    await roundTrip.EncryptAndSignAsync("short hash round trip"));
                decrypted.Trim().Should().Be("short hash round trip");
            }

            // Teardown
            testFactory.Teardown();
        }

        /// <summary>
        /// Digests that satisfy the algorithm's requirement must be honoured rather than silently upgraded.
        /// </summary>
        public static TheoryData<PublicKeyAlgorithmTag, int, HashAlgorithmTag> AcceptableCertificationHashes =>
            new TheoryData<PublicKeyAlgorithmTag, int, HashAlgorithmTag>
            {
                // RSA imposes no digest size requirement at all.
                { PublicKeyAlgorithmTag.RsaGeneral, 1024, HashAlgorithmTag.Sha224 },
                { PublicKeyAlgorithmTag.RsaGeneral, 1024, HashAlgorithmTag.Sha1 },
                // 160 bits is sufficient for a 1024 bit DSA key's 160 bit subgroup.
                { PublicKeyAlgorithmTag.Dsa, 1024, HashAlgorithmTag.Sha1 },
                { PublicKeyAlgorithmTag.Dsa, 1024, HashAlgorithmTag.Sha224 },
                // Stronger than required is always kept.
                { PublicKeyAlgorithmTag.EdDsa, 1024, HashAlgorithmTag.Sha512 },
                { PublicKeyAlgorithmTag.ECDsa, 1024, HashAlgorithmTag.Sha384 },
            };

        [Theory]
        [MemberData(nameof(AcceptableCertificationHashes))]
        public async Task GenerateKeyAsync_CertificationHashLongEnoughForAlgorithm_ShouldBeHonoured(
            PublicKeyAlgorithmTag algorithm, int strength, HashAlgorithmTag requestedHash)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = algorithm, HashAlgorithmTag = requestedHash };

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, testFactory.Password, strength: strength, certainty: 12);

            // Assert
            GetSelfCertificationHash(testFactory.PublicKeyFileInfo).Should().Be(requestedHash);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task GenerateKeyAsync_EncryptionOnlyMasterAlgorithm_ShouldThrowNotSupported()
        {
            // Arrange - ECDH cannot sign or certify, so it cannot be a master key. It is used as the
            // subkey algorithm automatically for EdDSA/ECDSA masters instead.
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.ECDH };

            // Act
            Func<Task> act = async () => await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo, testFactory.UserName, testFactory.Password,
                strength: 1024, certainty: 12);

            // Assert
            await act.Should().ThrowAsync<NotSupportedException>();

            // Teardown
            testFactory.Teardown();
        }
    }
}
