using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// Expired and revoked keys must not be chosen for encryption automatically - gpg refuses them
    /// without an explicit override, while PgpCore previously encrypted with them silently
    /// (GitHub issues #71 and #210). An explicit <see cref="EncryptionKeys.UseEncryptionKey"/> remains
    /// the override for callers who really do want an expired key.
    /// </summary>
    public class ExpiredKeySelection : TestBase
    {
        private static readonly Lazy<IAsymmetricCipherKeyPairGenerator> KeyPairGenerator =
            new Lazy<IAsymmetricCipherKeyPairGenerator>(() =>
            {
                RsaKeyPairGenerator kpg = new RsaKeyPairGenerator();
                kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));
                return kpg;
            });

        /// <summary>
        /// Builds a ring with a certify/sign master plus one encryption subkey per entry, where each
        /// entry controls its creation time and expiry so keys can be genuinely expired or current.
        /// </summary>
        private static PgpPublicKeyRing GenerateKeyRing(params (DateTime creationTime, long validSeconds)[] subKeys)
        {
            PgpKeyPair masterKey = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral,
                KeyPairGenerator.Value.GenerateKeyPair(), DateTime.UtcNow.AddYears(-3));

            PgpSignatureSubpacketGenerator masterSubpackets = new PgpSignatureSubpacketGenerator();
            masterSubpackets.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification,
                masterKey,
                "expiry@example.com",
                SymmetricKeyAlgorithmTag.Aes256,
                "password".ToCharArray(),
                true,
                masterSubpackets.Generate(),
                null,
                new SecureRandom());

            foreach ((DateTime creationTime, long validSeconds) in subKeys)
            {
                PgpKeyPair subKey = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral,
                    KeyPairGenerator.Value.GenerateKeyPair(), creationTime);

                PgpSignatureSubpacketGenerator subpackets = new PgpSignatureSubpacketGenerator();
                subpackets.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
                if (validSeconds > 0)
                    subpackets.SetKeyExpirationTime(false, validSeconds);

                keyRingGen.AddSubKey(subKey, subpackets.Generate(), null);
            }

            return keyRingGen.GeneratePublicKeyRing();
        }

        private static readonly long OneYearSeconds = (long)TimeSpan.FromDays(365).TotalSeconds;

        [Fact]
        public void FindBestEncryptionKey_OnlyExpiredEncryptionKeys_ShouldThrow()
        {
            // Arrange - created two years ago, expired after one.
            PgpPublicKeyRing ring = GenerateKeyRing((DateTime.UtcNow.AddYears(-2), OneYearSeconds));

            // Act
            Action act = () => Utilities.FindBestEncryptionKey(ring);

            // Assert
            act.Should().Throw<NoEncryptionKeyException>()
                .Which.Message.Should().Contain("expired").And.Contain("UseEncryptionKey");
        }

        [Fact]
        public void FindBestEncryptionKey_ExpiredAndCurrentSubKeys_ShouldPickTheCurrentOne()
        {
            // Arrange - the #210 scenario: the old subkey has expired and a replacement was issued.
            DateTime oldCreation = DateTime.UtcNow.AddYears(-2);
            DateTime newCreation = DateTime.UtcNow.AddDays(-30);
            PgpPublicKeyRing ring = GenerateKeyRing(
                (oldCreation, OneYearSeconds),
                (newCreation, 2 * OneYearSeconds));

            // Act
            PgpPublicKey selected = Utilities.FindBestEncryptionKey(ring);

            // Assert
            selected.CreationTime.Should().BeCloseTo(newCreation, TimeSpan.FromSeconds(2));
        }

        [Fact]
        public void FindBestEncryptionKey_TwoCurrentSubKeys_ShouldPickTheNewest()
        {
            // Arrange - both valid; the newer one should take over from the one it replaces.
            DateTime older = DateTime.UtcNow.AddYears(-1);
            DateTime newer = DateTime.UtcNow.AddDays(-7);
            PgpPublicKeyRing ring = GenerateKeyRing((older, 0), (newer, 0));

            // Act
            PgpPublicKey selected = Utilities.FindBestEncryptionKey(ring);

            // Assert
            selected.CreationTime.Should().BeCloseTo(newer, TimeSpan.FromSeconds(2));
        }

        [Fact]
        public void FindBestEncryptionKey_KeyWithNoExpirySet_ShouldNeverBeTreatedAsExpired()
        {
            // Arrange - a very old key with no expiry is still valid.
            PgpPublicKeyRing ring = GenerateKeyRing((DateTime.UtcNow.AddYears(-3), 0));

            // Act
            PgpPublicKey selected = Utilities.FindBestEncryptionKey(ring);

            // Assert
            selected.Should().NotBeNull();
        }

        [Fact]
        public void FindBestEncryptionKey_RevokedKey_ShouldThrow()
        {
            // Arrange - an encryption-capable master key carrying a revocation certification.
            PgpKeyPair masterKey = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral,
                KeyPairGenerator.Value.GenerateKeyPair(), DateTime.UtcNow.AddYears(-1));

            PgpSignatureSubpacketGenerator subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetKeyFlags(false,
                PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign |
                PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification, masterKey, "revoked@example.com",
                SymmetricKeyAlgorithmTag.Aes256, "password".ToCharArray(), true,
                subpackets.Generate(), null, new SecureRandom());

            PgpPublicKeyRing ring = keyRingGen.GeneratePublicKeyRing();
            PgpPublicKey publicKey = ring.GetPublicKeys().Cast<PgpPublicKey>().Single();

            PgpSignatureGenerator revocationGenerator =
                new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha256);
            revocationGenerator.InitSign(PgpSignature.KeyRevocation, masterKey.PrivateKey);
            PgpSignature revocation = revocationGenerator.GenerateCertification(publicKey);
            PgpPublicKey revokedKey = PgpPublicKey.AddCertification(publicKey, revocation);
            revokedKey.IsRevoked().Should().BeTrue("the arranged key must actually be revoked");

            PgpPublicKeyRing revokedRing = PgpPublicKeyRing.InsertPublicKey(ring, revokedKey);

            // Act
            Action act = () => Utilities.FindBestEncryptionKey(revokedRing);

            // Assert
            act.Should().Throw<NoEncryptionKeyException>();
        }

        [Fact]
        public void UseEncryptionKey_WithAnExpiredKey_ShouldStillActAsTheExplicitOverride()
        {
            // Arrange - pinning an expired key explicitly is the documented escape hatch, mirroring
            // gpg's expired-key override.
            PgpPublicKeyRing ring = GenerateKeyRing((DateTime.UtcNow.AddYears(-2), OneYearSeconds));
            PgpPublicKey expiredSubKey = ring.GetPublicKeys().Cast<PgpPublicKey>().Single(k => !k.IsMasterKey);

            PgpCore.Models.PgpPublicKeyRingWithPreferredKey wrapped =
                new PgpCore.Models.PgpPublicKeyRingWithPreferredKey(ring);

            // Act
            wrapped.UsePreferredEncryptionKey(expiredSubKey.KeyId);

            // Assert
            wrapped.PreferredEncryptionKey.Should().NotBeNull();
            wrapped.PreferredEncryptionKey.KeyId.Should().Be(expiredSubKey.KeyId);
        }
    }
}
