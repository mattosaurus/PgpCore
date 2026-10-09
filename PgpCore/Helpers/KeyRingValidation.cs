using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using System;
using System.Collections.Generic;
using System.IO;
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

            internal long ExpirationSeconds => PublicKey.Version <= 3
                ? PublicKey.GetValidSeconds()
                : Authorization?.GetHashedSubPackets()?.GetKeyExpirationTime() ?? 0;

            internal bool IsCurrent(DateTime now)
            {
                DateTime latestCreation = now.AddMinutes(5);
                if (Revoked || PublicKey.CreationTime > latestCreation)
                    return false;
                long keySeconds = ExpirationSeconds;
                if (keySeconds > 0 && (now - PublicKey.CreationTime).TotalSeconds >= keySeconds)
                    return false;
                if (Authorization != null)
                {
                    long signatureSeconds = Authorization.GetHashedSubPackets()?.GetSignatureExpirationTime() ?? 0;
                    if (Authorization.CreationTime > latestCreation ||
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
                    .Where(s => Verify(s, primary, copy => copy.VerifyCertification(primary, subkey)))
                    .OrderByDescending(s => s.CreationTime).FirstOrDefault();
                if (binding == null)
                    continue;

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
                if (Verify(signature, primary, copy => VerifyDirectKey(copy, primary)))
                    yield return signature;
            foreach (string userId in primary.GetUserIds())
                foreach (PgpSignature signature in SelfCertifications(primary, userId))
                    yield return signature;
            foreach (PgpUserAttributeSubpacketVector attribute in primary.GetUserAttributes())
                foreach (PgpSignature signature in primary.GetSignaturesForUserAttribute(attribute))
                    if (signature.SignatureType >= PgpSignature.DefaultCertification &&
                        signature.SignatureType <= PgpSignature.PositiveCertification &&
                        Verify(signature, primary, copy => copy.VerifyCertification(attribute, primary)))
                        yield return signature;
        }

        private static bool VerifyDirectKey(PgpSignature signature, PgpPublicKey key)
        {
            // BouncyCastle's single-key VerifyCertification accepts revocations only.
            // Use the framing belonging to the key version. Modern key packets have
            // a four-octet length even though the current signature reader is still limited.
            byte[] contents = key.PublicKeyPacket.GetEncodedContents();
            if (key.Version <= 4 && contents.Length > ushort.MaxValue) return false;
            signature.Update((byte)(key.Version <= 4 ? 0x99 : key.Version == 5 ? 0x9A : 0x9B));
            if (key.Version >= 5)
            {
                signature.Update((byte)(contents.Length >> 24));
                signature.Update((byte)(contents.Length >> 16));
            }
            signature.Update((byte)(contents.Length >> 8));
            signature.Update((byte)contents.Length);
            signature.Update(contents);
            return signature.Verify();
        }

        internal static string[] UserIds(PgpPublicKey primary) => primary.GetUserIds()
            .Where(id => SelfCertifications(primary, id).Any()).ToArray();

        private static IEnumerable<PgpSignature> SelfCertifications(PgpPublicKey primary, string userId)
        {
            PgpSignature[] signatures = primary.GetSignaturesForId(userId).ToArray();
            DateTime revokedAt = signatures.Where(s => s.SignatureType == PgpSignature.CertificationRevocation &&
                Verify(s, primary, copy => copy.VerifyCertification(userId, primary)))
                .Select(s => s.CreationTime).DefaultIfEmpty(DateTime.MinValue).Max();
            return signatures.Where(s => s.SignatureType >= PgpSignature.DefaultCertification &&
                s.SignatureType <= PgpSignature.PositiveCertification && s.CreationTime > revokedAt &&
                Verify(s, primary, copy => copy.VerifyCertification(userId, primary)));
        }

        private static bool HasRevocation(PgpPublicKey primary, PgpPublicKey key, int type)
        {
            return key.GetSignaturesOfType(type).Any(s => Verify(s, primary,
                copy => key.IsMasterKey ? copy.VerifyCertification(key) : copy.VerifyCertification(primary, key)));
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
            PgpSignatureList signatures;
            try { signatures = packets?.GetEmbeddedSignatures(); }
            catch (Exception error) when (IsUnverifiableSignature(error)) { return false; }
            if (signatures == null)
                return false;
            for (int i = 0; i < signatures.Count; i++)
            {
                PgpSignature signature = signatures[i];
                if (signature.SignatureType == PgpSignature.PrimaryKeyBinding &&
                    Verify(signature, subkey, copy => copy.VerifyCertification(primary, subkey)))
                    return true;
            }
            return false;
        }

        private static bool Verify(PgpSignature signature, PgpPublicKey signer, Func<PgpSignature, bool> verify)
        {
            try
            {
                // Rings and their signature objects are shared by independent lazies and callers.
                // Keep mutable verifier state private to this operation, including revocations.
                using var encoded = new MemoryStream(signature.GetEncoded(), false);
                var copy = ((PgpSignatureList)new PgpObjectFactory(encoded).NextPgpObject())[0];
                copy.InitVerify(signer);
                return verify(copy);
            }
            catch (Exception error) when (IsUnverifiableSignature(error)) { return false; }
        }

        private static bool IsUnverifiableSignature(Exception error) => error is PgpException ||
            error is ArgumentException || error is IOException || error is NotSupportedException ||
            error is UnsupportedPacketVersionException ||
            error is Org.BouncyCastle.Security.SecurityUtilityException;
    }
}
