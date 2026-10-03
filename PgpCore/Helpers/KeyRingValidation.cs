using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PgpCore.Helpers
{
    /// <summary>Authenticates certificate metadata before using it to authorize key operations.</summary>
    internal static class KeyRingValidation
    {
        internal sealed class Key
        {
            internal PgpPublicKey PublicKey;
            internal PgpSignature Authorization;
            internal bool Revoked;
            internal bool CanSign;
            internal bool CanEncrypt;

            internal bool IsCurrent(DateTime now)
            {
                if (Revoked || PublicKey.CreationTime > now)
                    return false;
                if (Authorization != null)
                {
                    long keySeconds = Authorization.GetHashedSubPackets()?.GetKeyExpirationTime() ?? 0;
                    long signatureSeconds = Authorization.GetHashedSubPackets()?.GetSignatureExpirationTime() ?? 0;
                    if (Authorization.CreationTime > now ||
                        keySeconds > 0 && (now - PublicKey.CreationTime).TotalSeconds >= keySeconds ||
                        signatureSeconds > 0 && (now - Authorization.CreationTime).TotalSeconds >= signatureSeconds)
                        return false;
                }
                return true;
            }
        }

        internal static Key[] Read(PgpPublicKeyRing ring)
        {
            PgpPublicKey primary = ring.GetPublicKey();
            if (primary == null || !primary.IsMasterKey)
                throw new InvalidKeyMaterialException("A key ring must start with its primary key.");

            PgpSignature[] selfSignatures = ReadSelfSignatures(primary).ToArray();
            if (primary.Version >= 4 && selfSignatures.Length == 0)
                throw new InvalidKeyMaterialException("The primary key has no valid self-signature.");
            var primaryInfo = Create(primary, selfSignatures.OrderByDescending(s => s.CreationTime).FirstOrDefault(),
                HasRevocation(primary, primary, PgpSignature.KeyRevocation));
            var keys = new List<Key> { primaryInfo };
            foreach (PgpPublicKey subkey in ring.GetPublicKeys().Where(k => !k.IsMasterKey))
            {
                PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding)
                    .Where(s => Verify(s, primary, () => s.VerifyCertification(primary, subkey)))
                    .OrderByDescending(s => s.CreationTime).FirstOrDefault();
                if (binding == null)
                    throw new InvalidKeyMaterialException($"Subkey [{subkey.KeyId:X}] has no valid binding to the primary key.");

                var info = Create(subkey, binding,
                    primaryInfo.Revoked || HasRevocation(primary, subkey, PgpSignature.SubkeyRevocation));
                if (info.CanSign && !HasBackSignature(primary, subkey, binding))
                    info.CanSign = false;
                keys.Add(info);
            }
            return keys.ToArray();
        }

        internal static IEnumerable<Key> EncryptionKeys(PgpPublicKeyRing ring, bool requireCurrent)
        {
            Key[] keys = Read(ring);
            DateTime now = DateTime.UtcNow;
            if (requireCurrent && !keys[0].IsCurrent(now))
                return Enumerable.Empty<Key>();
            return keys.Where(k => k.CanEncrypt && (!requireCurrent || k.IsCurrent(now)));
        }

        internal static IEnumerable<Key> SigningKeys(PgpPublicKeyRing ring, bool requireCurrent)
        {
            Key[] keys = Read(ring);
            DateTime now = DateTime.UtcNow;
            if (requireCurrent && !keys[0].IsCurrent(now))
                return Enumerable.Empty<Key>();
            return keys.Where(k => k.CanSign && (!requireCurrent || k.IsCurrent(now)));
        }

        private static Key Create(PgpPublicKey key, PgpSignature authorization, bool revoked)
        {
            var packets = authorization?.GetHashedSubPackets();
            bool flagsPresent = packets != null && packets.HasSubpacket(SignatureSubpacketTag.KeyFlags);
            int flags = packets?.GetKeyFlags() ?? 0;
            bool signingAlgorithm = key.Algorithm == PublicKeyAlgorithmTag.RsaGeneral ||
                key.Algorithm == PublicKeyAlgorithmTag.RsaSign || key.Algorithm == PublicKeyAlgorithmTag.Dsa ||
                key.Algorithm == PublicKeyAlgorithmTag.ECDsa || key.Algorithm == PublicKeyAlgorithmTag.EdDsa_Legacy;
            return new Key
            {
                PublicKey = key,
                Authorization = authorization,
                Revoked = revoked,
                CanSign = signingAlgorithm && (!flagsPresent || (flags & KeyFlags.SignData) != 0),
                CanEncrypt = key.IsEncryptionKey && (!flagsPresent || (flags & (KeyFlags.EncryptComms | KeyFlags.EncryptStorage)) != 0)
            };
        }

        private static IEnumerable<PgpSignature> ReadSelfSignatures(PgpPublicKey primary)
        {
            foreach (PgpSignature signature in primary.GetSignaturesOfType(PgpSignature.DirectKey))
                if (Verify(signature, primary, () => signature.VerifyCertification(primary)))
                    yield return signature;
            foreach (string userId in primary.GetUserIds())
                foreach (PgpSignature signature in SelfCertifications(primary, userId))
                    yield return signature;
            foreach (PgpUserAttributeSubpacketVector attribute in primary.GetUserAttributes())
                foreach (PgpSignature signature in primary.GetSignaturesForUserAttribute(attribute))
                    if (signature.SignatureType >= PgpSignature.DefaultCertification &&
                        signature.SignatureType <= PgpSignature.PositiveCertification &&
                        Verify(signature, primary, () => signature.VerifyCertification(attribute, primary)))
                        yield return signature;
        }

        internal static string[] UserIds(PgpPublicKey primary) => primary.GetUserIds()
            .Where(id => SelfCertifications(primary, id).Any()).ToArray();

        private static IEnumerable<PgpSignature> SelfCertifications(PgpPublicKey primary, string userId)
        {
            PgpSignature[] signatures = primary.GetSignaturesForId(userId).ToArray();
            DateTime revokedAt = signatures.Where(s => s.SignatureType == PgpSignature.CertificationRevocation &&
                Verify(s, primary, () => s.VerifyCertification(userId, primary)))
                .Select(s => s.CreationTime).DefaultIfEmpty(DateTime.MinValue).Max();
            return signatures.Where(s => s.SignatureType >= PgpSignature.DefaultCertification &&
                s.SignatureType <= PgpSignature.PositiveCertification && s.CreationTime > revokedAt &&
                Verify(s, primary, () => s.VerifyCertification(userId, primary)));
        }

        private static bool HasRevocation(PgpPublicKey primary, PgpPublicKey key, int type)
        {
            return key.GetSignaturesOfType(type).Any(s => Verify(s, primary,
                () => key.IsMasterKey ? s.VerifyCertification(key) : s.VerifyCertification(primary, key)));
        }

        private static bool HasBackSignature(PgpPublicKey primary, PgpPublicKey subkey, PgpSignature binding)
        {
            // Both locations occur in existing v4 certificates. Authenticate the embedded
            // signature itself even when it resides in the unhashed area of the binding.
            return HasBackSignature(primary, subkey, binding.GetHashedSubPackets()) ||
                HasBackSignature(primary, subkey, binding.GetUnhashedSubPackets());
        }

        private static bool HasBackSignature(PgpPublicKey primary, PgpPublicKey subkey, PgpSignatureSubpacketVector packets)
        {
            PgpSignatureList signatures = packets?.GetEmbeddedSignatures();
            if (signatures == null)
                return false;
            for (int i = 0; i < signatures.Count; i++)
            {
                PgpSignature signature = signatures[i];
                if (signature.SignatureType == PgpSignature.PrimaryKeyBinding &&
                    Verify(signature, subkey, () => signature.VerifyCertification(primary, subkey)))
                    return true;
            }
            return false;
        }

        private static bool Verify(PgpSignature signature, PgpPublicKey signer, Func<bool> verify)
        {
            try
            {
                signature.InitVerify(signer);
                return verify();
            }
            catch (PgpException) { return false; }
            catch (ArgumentException) { return false; }
        }
    }
}
