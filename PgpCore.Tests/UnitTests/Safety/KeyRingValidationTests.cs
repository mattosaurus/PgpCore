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
        [InlineData(4, false)]
        [InlineData(4, true)]
        [InlineData(5, false)]
        [InlineData(5, true)]
        [InlineData(6, false)]
        [InlineData(6, true)]
        public void DirectKeySelfSignature_IsAuthenticatedWithoutRequiringUserIds(int keyVersion, bool authentic)
        {
            var primary = Pair();
            var publicKey = keyVersion == 4 ? primary.PublicKey : new PgpPublicKey(new PublicKeyPacket(
                (byte)keyVersion, primary.PublicKey.Algorithm, primary.PublicKey.CreationTime, primary.PublicKey.PublicKeyPacket.Key));
            var signer = authentic ? primary : Pair();
            var signature = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.DirectKey, signer.PrivateKey);
            var packets = new PgpSignatureSubpacketGenerator();
            packets.SetKeyFlags(false, KeyFlags.EncryptComms);
            signature.SetHashedSubpackets(packets.Generate());
            PgpSignature certification;
            if (keyVersion == 4)
                certification = signature.GenerateCertification(publicKey);
            else
            {
                // Isolate key framing with a v4 signature, supported by this BouncyCastle reader.
                // This does not claim support for v5/v6 signature packets.
                byte[] contents = publicKey.PublicKeyPacket.GetEncodedContents();
                signature.Update(new[] { (byte)(keyVersion == 5 ? 0x9A : 0x9B),
                    (byte)(contents.Length >> 24), (byte)(contents.Length >> 16),
                    (byte)(contents.Length >> 8), (byte)contents.Length });
                signature.Update(contents);
                certification = signature.Generate();
            }
            var key = PgpPublicKey.AddCertification(publicKey, certification);
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
        public void AppendedForeignSubkey_IsExcludedWhileAuthenticKeysRemainUsable()
        {
            var trustedGenerator = Ring(Pair());
            var encryptionKey = Pair();
            var flags = new PgpSignatureSubpacketGenerator();
            flags.SetKeyFlags(false, KeyFlags.EncryptComms);
            trustedGenerator.AddSubKey(encryptionKey, flags.Generate(), null, HashAlgorithmTag.Sha256);
            var trusted = trustedGenerator.GeneratePublicKeyRing();
            var foreign = Ring(Pair());
            foreign.AddSubKey(Pair(), HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha256);
            var subkey = foreign.GeneratePublicKeyRing().GetPublicKeys().Last();
            var modified = PgpPublicKeyRing.InsertPublicKey(trusted, subkey);
            Assert.Equal(trusted.GetPublicKey().GetFingerprint(), modified.GetPublicKey().GetFingerprint());
            Assert.Single(Keys(modified).VerificationKeys);
            Assert.Throws<MissingKeyException>(() => Keys(modified).UseEncryptionKey(subkey.KeyId));
            Assert.Equal(encryptionKey.KeyId, Utilities.FindBestEncryptionKey(modified).KeyId);
            using var encoded = new MemoryStream();
            modified.Encode(encoded);
            encoded.Position = 0;
            var inspected = PGP.InspectKeys(encoded);
            Assert.Equal(2, inspected.Count);
            Assert.DoesNotContain(inspected, key => key.Fingerprint == BitConverter.ToString(subkey.GetFingerprint()).Replace("-", ""));
        }

        [Fact]
        public void CertificateValidation_DoesNotMutateCallerOwnedSignatureState()
        {
            var ring = Ring(Pair(), KeyFlags.SignData | KeyFlags.EncryptComms).GeneratePublicKeyRing();
            var primary = ring.GetPublicKey();
            const string userId = "certificate@example.test";
            var signature = primary.GetSignaturesForId(userId).Single();
            byte[] key = primary.PublicKeyPacket.GetEncodedContents();
            byte[] id = Encoding.UTF8.GetBytes(userId);
            signature.InitVerify(primary);
            signature.Update((byte)0x99);
            // Another operation can validate this same ring while its caller is verifying a certification.
            Assert.Equal(primary.KeyId, Utilities.FindBestEncryptionKey(ring).KeyId);
            signature.Update((byte)(key.Length >> 8));
            signature.Update((byte)key.Length);
            signature.Update(key);
            signature.Update(new byte[] { 0xB4, 0, 0, 0, (byte)id.Length });
            signature.Update(id);
            Assert.True(signature.Verify());
        }

        [Fact]
        public void SharedCertificate_ValidatesConcurrently()
        {
            var ring = Ring(Pair(), KeyFlags.SignData | KeyFlags.EncryptComms).GeneratePublicKeyRing();
            var wrapper = new PgpCore.Models.PgpPublicKeyRingWithPreferredKey(ring);
            Parallel.For(0, 64, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
            {
                Assert.Equal(ring.GetPublicKey().KeyId, Utilities.FindBestEncryptionKey(ring).KeyId);
                Assert.Equal(ring.GetPublicKey().KeyId, wrapper.DefaultEncryptionKey.KeyId);
                wrapper.UsePreferredEncryptionKey(ring.GetPublicKey().KeyId);
            });
        }

        [Theory]
        [InlineData(2, 0, true)]
        [InlineData(0, 2, true)]
        [InlineData(20, 0, false)]
        [InlineData(0, 20, false)]
        public void CreationTimes_AllowSmallClockSkewButRejectFarFutureKeys(int keyMinutes, int signatureMinutes, bool usable)
        {
            var primary = Pair(DateTime.UtcNow.AddMinutes(keyMinutes));
            var signature = new PgpSignatureGenerator(primary.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.DirectKey, primary.PrivateKey);
            var packets = new PgpSignatureSubpacketGenerator();
            packets.SetSignatureCreationTime(false, DateTime.UtcNow.AddMinutes(signatureMinutes));
            packets.SetKeyFlags(false, KeyFlags.SignData | KeyFlags.EncryptComms);
            signature.SetHashedSubpackets(packets.Generate());
            var key = PgpPublicKey.AddCertification(primary.PublicKey, signature.GenerateCertification(primary.PublicKey));
            using var encoded = new MemoryStream();
            key.Encode(encoded);
            encoded.Position = 0;
            var info = Assert.Single(PGP.InspectKeys(encoded));
            Assert.Equal(usable, info.IsUsableForEncryption);
            Assert.Equal(usable, info.IsUsableForSigning);
            Assert.Matches("^[0-9A-F]{16}$", info.KeyId);
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
        public void UnsupportedEmbeddedBackSignature_DoesNotDisableEncryptionOrThePrimaryKey()
        {
            var generator = Ring(Pair());
            var subkey = Pair();
            var flags = new PgpSignatureSubpacketGenerator();
            flags.SetKeyFlags(false, KeyFlags.SignData | KeyFlags.EncryptComms);
            var unhashed = new PgpSignatureSubpacketGenerator();
            // An unsupported embedded signature can occur in a binding's unauthenticated area.
            unhashed.AddCustomSubpacket(new EmbeddedSignature(false, false, new byte[] { 5, 0, 0, 0 }));
            generator.AddSubKey(subkey, flags.Generate(), unhashed.Generate(), HashAlgorithmTag.Sha256);
            var ring = generator.GeneratePublicKeyRing();
            Assert.Single(Keys(ring).VerificationKeys);
            Assert.Equal(subkey.KeyId, Utilities.FindBestEncryptionKey(ring).KeyId);
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
