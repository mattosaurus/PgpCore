using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using PgpCore.Abstractions;
using System.IO;
using System;
using Org.BouncyCastle.Math;

namespace PgpCore
{
    public partial class PGP : IKeySync
    {
        public void GenerateKey(
            FileInfo publicKeyFileInfo,
            FileInfo privateKeyFileInfo,
            string username = null,
            string password = null,
            int strength = 3072,
            int certainty = 24,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymmetricKeyAlgorithms = null)
        {
            if (publicKeyFileInfo == null)
                throw new ArgumentNullException(nameof(publicKeyFileInfo));
            if (privateKeyFileInfo == null)
                throw new ArgumentNullException(nameof(privateKeyFileInfo));

            using (Stream pubs = publicKeyFileInfo.Create())
            using (Stream pris = privateKeyFileInfo.Create())
                GenerateKey(pubs, pris, username, password, strength, certainty, armor, emitVersion,
                    keyExpirationInSeconds, signatureExpirationInSeconds,
                    preferredCompressionAlgorithms, preferredHashAlgorithmTags, preferredSymmetricKeyAlgorithms);
        }

        public void GenerateKey(
            Stream publicKeyStream,
            Stream privateKeyStream,
            string username = null,
            string password = null,
            int strength = 3072,
            int certainty = 24,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymmetricKeyAlgorithms = null)
        {
            username = username ?? string.Empty;
            password = password ?? string.Empty;

            preferredCompressionAlgorithms = preferredCompressionAlgorithms ??
                ((CompressionAlgorithm != CompressionAlgorithmTag.Zip && CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed) ?
                new[]
                {
                    CompressionAlgorithm,
                    CompressionAlgorithmTag.Zip,
                    CompressionAlgorithmTag.Uncompressed,
                } :
                new[]
                {
                    CompressionAlgorithmTag.Zip,
                    CompressionAlgorithmTag.Uncompressed,
                });

            preferredHashAlgorithmTags = preferredHashAlgorithmTags ??
                (HashAlgorithmTag == HashAlgorithmTag.Sha1 ?
                new[]
                {
                    HashAlgorithmTag
                } :
                new[]
                {
                    HashAlgorithmTag, HashAlgorithmTag.Sha1
                });

            preferredSymmetricKeyAlgorithms = preferredSymmetricKeyAlgorithms ??
                (SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.TripleDes ?
                new[]
                {
                    SymmetricKeyAlgorithm
                } :
                new[]
                {
                    SymmetricKeyAlgorithm, SymmetricKeyAlgorithmTag.TripleDes
                });

            PgpKeyPair masterKey = GenerateMasterKeyPair(strength, certainty);
            PgpKeyPair encryptionSubKey = GenerateEncryptionSubKeyPair(strength, certainty);

            // EdDSA/ECDSA (and large DSA) self-certifications require SHA-256+, so promote a SHA-1
            // certification hash for those algorithms. RSA (and any explicitly stronger hash) is left unchanged.
            HashAlgorithmTag certificationHashAlgorithm = GetCertificationHashAlgorithm(preferredHashAlgorithmTags[0], strength);

            // The master key certifies and signs; encryption is delegated to the subkey added below. Without
            // that split, signature-only algorithms (EdDSA, ECDSA, DSA) produce a key that cannot encrypt at
            // all, and RSA keys use a single key for everything unlike every mainstream implementation (#285).
            PgpSignatureSubpacketGenerator signHashGen = new PgpSignatureSubpacketGenerator();
            signHashGen.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            signHashGen.SetPreferredCompressionAlgorithms(false, Array.ConvertAll(preferredCompressionAlgorithms, item => (int)item));
            signHashGen.SetPreferredHashAlgorithms(false, Array.ConvertAll(preferredHashAlgorithmTags, item => (int)item));
            signHashGen.SetPreferredSymmetricAlgorithms(false, Array.ConvertAll(preferredSymmetricKeyAlgorithms, item => (int)item));
            signHashGen.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            signHashGen.SetKeyExpirationTime(false, keyExpirationInSeconds);
            signHashGen.SetSignatureExpirationTime(false, signatureExpirationInSeconds);

            PgpSignatureSubpacketGenerator encryptionSubKeyHashGen = new PgpSignatureSubpacketGenerator();
            encryptionSubKeyHashGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            encryptionSubKeyHashGen.SetKeyExpirationTime(false, keyExpirationInSeconds);
            encryptionSubKeyHashGen.SetSignatureExpirationTime(false, signatureExpirationInSeconds);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignatureType,
                masterKey,
                username,
                SymmetricKeyAlgorithm,
                certificationHashAlgorithm,
                password.ToCharArray(),
                certificationHashAlgorithm == HashAlgorithmTag.Sha1,
                signHashGen.Generate(),
                null,
                new SecureRandom());

            keyRingGen.AddSubKey(encryptionSubKey, encryptionSubKeyHashGen.Generate(), null, certificationHashAlgorithm);

            ExportKeyRing(privateKeyStream, publicKeyStream, keyRingGen.GenerateSecretKeyRing(),
                keyRingGen.GeneratePublicKeyRing(), armor, emitVersion);
        }
    }
}
