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
        public async Task CertificationIssuer_DoesNotRedirectSigningSubkeyLookup()
        {
            var primary = Pair();
            var signer = Pair();
            var generator = Ring(primary);
            var flags = new PgpSignatureSubpacketGenerator();
            flags.SetKeyFlags(false, KeyFlags.SignData);
            generator.AddSubKey(signer, flags.Generate(), null, HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha256);
            var ring = generator.GeneratePublicKeyRing();
            var certification = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            certification.InitSign(PgpSignature.DirectKey, signer.PrivateKey);
            // An issuer on a primary certificate must never masquerade as that primary's key ID.
            ring = PgpPublicKeyRing.InsertPublicKey(ring, PgpPublicKey.AddCertification(ring.GetPublicKey(),
                certification.GenerateCertification(ring.GetPublicKey())));
            var keys = Keys(ring);
            Assert.True(Utilities.FindPublicKey(signer.KeyId, keys.VerificationKeys, out var found));
            Assert.Equal(signer.KeyId, found.KeyId);
            byte[] payload = Encoding.UTF8.GetBytes("authenticated subkey signature");
            var signature = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.BinaryDocument, signer.PrivateKey);
            signature.Update(payload);
            using var signed = new MemoryStream();
            signature.Generate().Encode(signed);
            signed.Position = 0;
            using var input = new MemoryStream(payload);
            Assert.True(await new PGP(keys).VerifyDetachedAsync(input, signed));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void DirectKeySelfSignature_IsAuthenticatedWithoutRequiringUserIds(bool authentic)
        {
            var primary = Pair();
            var signer = authentic ? primary : Pair();
            var signature = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.DirectKey, signer.PrivateKey);
            var packets = new PgpSignatureSubpacketGenerator();
            packets.SetKeyFlags(false, KeyFlags.EncryptComms);
            signature.SetHashedSubpackets(packets.Generate());
            var key = PgpPublicKey.AddCertification(primary.PublicKey, signature.GenerateCertification(primary.PublicKey));
            using var encoded = new MemoryStream();
            key.Encode(encoded);
            encoded.Position = 0;
            if (!authentic) Assert.Throws<InvalidKeyMaterialException>(() => PGP.InspectKeys(encoded));
            else
            {
                var info = Assert.Single(PGP.InspectKeys(encoded));
                Assert.True(info.IsUsableForEncryption);
                Assert.False(info.CanSign);
                Assert.Empty(info.UserIds);
            }
        }

        [Theory]
        [InlineData(0, true)]
        [InlineData(1, false)]
        [InlineData(7, true)]
        public void LegacyV3Keys_RespectNativeValidityDays(int days, bool usable)
        {
            DateTime created = DateTime.UtcNow.AddDays(-2);
            var pair = Pair(created);
            byte[] contents = new PublicKeyPacket(3, pair.PublicKey.Algorithm, created,
                pair.PublicKey.PublicKeyPacket.Key).GetEncodedContents();
            contents[5] = (byte)(days >> 8);
            contents[6] = (byte)days;
            using var encoded = new MemoryStream();
            // Encode a native v3 primary packet: version, timestamp, validity days, RSA MPIs.
            encoded.WriteByte(0xC0 | (byte)PacketTag.PublicKey);
            encoded.WriteByte((byte)contents.Length);
            encoded.Write(contents);
            encoded.Position = 0;
            var ring = new PgpPublicKeyRing(encoded);
            encoded.Position = 0;
            var info = PGP.InspectKeys(encoded)[0];
            Assert.Equal(usable, info.IsUsableForEncryption);
            Assert.Equal(usable, info.IsUsableForSigning);
            Assert.Equal(days == 0 ? (DateTime?)null : ring.GetPublicKey().CreationTime.AddDays(days), info.Expiration);
            if (usable) Assert.Equal(ring.GetPublicKey().KeyId, Utilities.FindBestEncryptionKey(ring).KeyId);
            else Assert.Throws<NoEncryptionKeyException>(() => Utilities.FindBestEncryptionKey(ring));
            Assert.Single(Keys(ring).VerificationKeys); // Historical verification remains available.
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
