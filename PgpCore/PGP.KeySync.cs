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
            int strength = 1024,
            int certainty = 8,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null)
        {
            if (publicKeyFileInfo == null)
                throw new ArgumentException("PublicKeyFileInfo");
            if (privateKeyFileInfo == null)
                throw new ArgumentException("PrivateKeyFileInfo");

            using (Stream pubs = publicKeyFileInfo.Create())
            using (Stream pris = privateKeyFileInfo.Create())
                GenerateKey(pubs, pris, username, password, strength, certainty, armor, emitVersion,
                    keyExpirationInSeconds, signatureExpirationInSeconds,
                    preferredCompressionAlgorithms, preferredHashAlgorithmTags, preferredSymetricKeyAlgorithms);
        }

        public void GenerateKey(
            Stream publicKeyStream,
            Stream privateKeyStream,
            string username = null,
            string password = null,
            int strength = 1024,
            int certainty = 8,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null)
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

            preferredSymetricKeyAlgorithms = preferredSymetricKeyAlgorithms ??
                (SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.TripleDes ?
                new[]
                {
                    SymmetricKeyAlgorithm
                } :
                new[]
                {
                    SymmetricKeyAlgorithm, SymmetricKeyAlgorithmTag.TripleDes
                });

            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();

            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));

            PgpKeyPair masterKey = new PgpKeyPair(PublicKeyAlgorithm, kpg.GenerateKeyPair(), DateTime.UtcNow);

            PgpSignatureSubpacketGenerator signHashGen = new PgpSignatureSubpacketGenerator();
            signHashGen.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage | PgpKeyFlags.CanSign);
            signHashGen.SetPreferredCompressionAlgorithms(false, Array.ConvertAll(preferredCompressionAlgorithms, item => (int)item));
            signHashGen.SetPreferredHashAlgorithms(false, Array.ConvertAll(preferredHashAlgorithmTags, item => (int)item));
            signHashGen.SetPreferredSymmetricAlgorithms(false, Array.ConvertAll(preferredSymetricKeyAlgorithms, item => (int)item));
            signHashGen.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            signHashGen.SetKeyExpirationTime(false, keyExpirationInSeconds);
            signHashGen.SetSignatureExpirationTime(false, signatureExpirationInSeconds);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignatureType,
                masterKey,
                username,
                SymmetricKeyAlgorithm,
                password.ToCharArray(),
                true,
                signHashGen.Generate(),
                null,
                new SecureRandom());

            PgpSecretKeyRing secretKeyRing = keyRingGen.GenerateSecretKeyRing();

            ExportKeyPair(privateKeyStream, publicKeyStream, secretKeyRing.GetSecretKey(), armor, emitVersion);
        }
    }
}
