using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Safety
{
    public class KeyRingValidationTests
    {
        private static PgpKeyPair Pair(DateTime? created = null)
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 1024, 8));
            return new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), created ?? DateTime.UtcNow);
        }

        private static PgpKeyRingGenerator Ring(PgpKeyPair primary, int flags = KeyFlags.SignData | KeyFlags.CertifyOther, long expiry = 0)
        {
            var packets = new PgpSignatureSubpacketGenerator();
            packets.SetKeyFlags(false, flags);
            packets.SetKeyExpirationTime(false, expiry);
            return new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "certificate@example.test",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, Array.Empty<char>(), false,
                packets.Generate(), null, new SecureRandom());
        }

        private static EncryptionKeys Keys(PgpPublicKeyRing ring)
        {
            using var encoded = new MemoryStream();
            ring.Encode(encoded);
            encoded.Position = 0;
            return new EncryptionKeys(encoded);
        }

        [Fact]
        public void AppendedForeignSubkey_IsRejectedForVerificationAndEncryptionSelection()
        {
            var trusted = Ring(Pair()).GeneratePublicKeyRing();
            var foreign = Ring(Pair());
            foreign.AddSubKey(Pair(), HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha256);
            var subkey = foreign.GeneratePublicKeyRing().GetPublicKeys().Last();
            var modified = PgpPublicKeyRing.InsertPublicKey(trusted, subkey);
            Assert.Equal(trusted.GetPublicKey().GetFingerprint(), modified.GetPublicKey().GetFingerprint());
            Assert.Throws<InvalidKeyMaterialException>(() => Keys(modified).VerificationKeys.ToArray());
            Assert.Throws<InvalidKeyMaterialException>(() => Keys(modified).UseEncryptionKey(subkey.KeyId));
            Assert.Throws<InvalidKeyMaterialException>(() => Utilities.FindBestEncryptionKey(modified));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task SigningSubkey_RequiresBackSignatureAndValidBindingsRemainUsable(bool backSignature)
        {
            var primary = Pair();
            var subkey = Pair();
            var ring = Ring(primary);
            var packets = new PgpSignatureSubpacketGenerator();
            packets.SetKeyFlags(false, KeyFlags.SignData);
            if (backSignature)
                ring.AddSubKey(subkey, packets.Generate(), null, HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha256);
            else
                ring.AddSubKey(subkey, packets.Generate(), null, HashAlgorithmTag.Sha256);
            var keys = Keys(ring.GeneratePublicKeyRing());
            Assert.Equal(backSignature, keys.VerificationKeys.Any(k => k.KeyId == subkey.KeyId));
            byte[] bytes = Encoding.UTF8.GetBytes("subkey payload");
            var signature = new PgpSignatureGenerator(subkey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.BinaryDocument, subkey.PrivateKey);
            signature.Update(bytes);
            using var input = new MemoryStream(bytes);
            using var output = new MemoryStream();
            signature.Generate().Encode(output);
            output.Position = 0;
            Assert.Equal(backSignature, await new PGP(keys).VerifyDetachedAsync(input, output));
        }

        [Fact]
        public void EncryptionOnlySubkey_CannotAuthorizeSignatures()
        {
            var ring = Ring(Pair());
            var packets = new PgpSignatureSubpacketGenerator();
            packets.SetKeyFlags(false, KeyFlags.EncryptComms);
            ring.AddSubKey(Pair(), packets.Generate(), null, HashAlgorithmTag.Sha256);
            var publicRing = ring.GeneratePublicKeyRing();
            Assert.Equal(publicRing.GetPublicKeys().Last().KeyId, Utilities.FindBestEncryptionKey(publicRing).KeyId);
            Assert.Single(Keys(publicRing).VerificationKeys);
        }

        [Fact]
        public void ForgedRevocation_DoesNotDisableAuthenticEncryptionKey()
        {
            var primary = Pair();
            var publicRing = Ring(primary, KeyFlags.SignData | KeyFlags.EncryptComms).GeneratePublicKeyRing();
            var attacker = Pair();
            var generator = new PgpSignatureGenerator(attacker.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, attacker.PrivateKey);
            PgpPublicKey forged = PgpPublicKey.AddCertification(publicRing.GetPublicKey(), generator.GenerateCertification(publicRing.GetPublicKey()));
            publicRing = PgpPublicKeyRing.InsertPublicKey(publicRing, forged);
            Assert.Equal(primary.KeyId, Utilities.FindBestEncryptionKey(publicRing).KeyId);
        }

        [Fact]
        public void Inspection_ExcludesUserIdsWithoutAuthenticSelfCertification()
        {
            var ring = Ring(Pair()).GeneratePublicKeyRing();
            var attacker = Pair();
            var signature = new PgpSignatureGenerator(attacker.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.PositiveCertification, attacker.PrivateKey);
            const string injected = "trusted-looking@example.test";
            var modified = PgpPublicKey.AddCertification(ring.GetPublicKey(), injected,
                signature.GenerateCertification(injected, ring.GetPublicKey()));
            ring = PgpPublicKeyRing.InsertPublicKey(ring, modified);
            using var encoded = new MemoryStream();
            ring.Encode(encoded);
            encoded.Position = 0;
            Assert.Equal(new[] { "certificate@example.test" }, PGP.InspectKeys(encoded)[0].UserIds);
        }

        [Fact]
        public void ExpiredPrimary_DisablesNewSigningButAllowsHistoricalVerification()
        {
            var primary = Pair(DateTime.UtcNow.AddDays(-2));
            var generator = Ring(primary, expiry: 60);
            using var encoded = new MemoryStream();
            generator.GenerateSecretKeyRing().Encode(encoded);
            encoded.Position = 0;
            var keys = new EncryptionKeys(encoded, "");
            Assert.Single(keys.VerificationKeys);
            Assert.Throws<NoSigningKeyException>(() => keys.SigningSecretKey);
        }
    }
}
