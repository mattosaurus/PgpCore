using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;

namespace PgpCore
{
    public partial class PGP
    {
        /// <summary>Smallest DSA key size BouncyCastle will generate.</summary>
        private const int MinimumDsaStrength = 512;

        /// <summary>Largest DSA key size handled by BouncyCastle's legacy (FIPS 186-2) generator.</summary>
        private const int MaximumLegacyDsaStrength = 1024;

        /// <summary>Subgroup (q) size used for DSA keys above the legacy limit, per FIPS 186-3.</summary>
        private const int LargeDsaSubgroupSize = 256;

        /// <summary>
        /// Generates a master <see cref="PgpKeyPair"/> for the currently configured
        /// <see cref="PublicKeyAlgorithm"/>. Prior to this the generator was hardcoded to RSA which meant
        /// that setting a non-RSA <see cref="PublicKeyAlgorithmTag"/> produced an "invalid key" from
        /// BouncyCastle because the requested tag did not match the underlying key material (GitHub issue #285).
        /// </summary>
        /// <param name="strength">Key strength in bits (used by RSA and DSA).</param>
        /// <param name="certainty">Primality certainty (used by RSA and DSA).</param>
        /// <returns>A master key pair carrying the correct algorithm tag for the generated key material.</returns>
        /// <exception cref="NotSupportedException">Thrown when key generation for the configured algorithm is not supported.</exception>
        private PgpKeyPair GenerateMasterKeyPair(int strength, int certainty)
        {
            DateTime creationTime = DateTime.UtcNow;
            SecureRandom secureRandom = new SecureRandom();

            switch (PublicKeyAlgorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaEncrypt:
                {
                    IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
                    kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), secureRandom, strength, certainty));
                    return new PgpKeyPair(PublicKeyAlgorithm, kpg.GenerateKeyPair(), creationTime);
                }

                case PublicKeyAlgorithmTag.EdDsa:
                {
                    // Ed25519 signing key. The generator ignores strength/certainty; the curve is fixed.
                    Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
                    kpg.Init(new Ed25519KeyGenerationParameters(secureRandom));
                    return new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, kpg.GenerateKeyPair(), creationTime);
                }

                case PublicKeyAlgorithmTag.ECDsa:
                {
                    // NIST P-256 (secp256r1) named curve. Passing the OID keeps the parameters as a named curve
                    // in the exported key, which is what OpenPGP consumers expect.
                    ECKeyPairGenerator kpg = new ECKeyPairGenerator("ECDSA");
                    kpg.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, secureRandom));
                    return new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, kpg.GenerateKeyPair(), creationTime);
                }

                case PublicKeyAlgorithmTag.Dsa:
                    return new PgpKeyPair(PublicKeyAlgorithmTag.Dsa,
                        GenerateDsaKeyPair(strength, certainty, secureRandom), creationTime);

                default:
                    throw new NotSupportedException(
                        $"Key generation for {PublicKeyAlgorithm} is not supported. " +
                        "Supported algorithms are RsaGeneral/RsaSign/RsaEncrypt, EdDsa (Ed25519), ECDsa (NIST P-256) and Dsa. " +
                        "Encryption-only algorithms cannot be used for the master key; an encryption subkey is generated automatically.");
            }
        }

        /// <summary>
        /// Generates the encryption subkey that accompanies the master key.
        /// <para>
        /// The master key certifies and signs only, so without a subkey a generated key cannot encrypt at
        /// all. That is why EdDSA and ECDSA keys previously failed with "passed in key not an encryption
        /// key!" - those algorithms cannot encrypt, and no separate encryption key was being created
        /// (GitHub issue #285).
        /// </para>
        /// <para>
        /// The subkey algorithm is chosen to match the master key: RSA masters get an RSA subkey, Ed25519
        /// gets X25519 ECDH and ECDSA gets ECDH on the same curve (both as gpg pairs them). DSA gets an RSA
        /// subkey rather than the traditional ElGamal one: BouncyCastle's ElGamal parameter generation takes
        /// minutes beyond 1024 bits (measured at over two minutes for 2048), which would make DSA key
        /// generation appear to hang at the default strength. RFC 4880 does not require the subkey algorithm
        /// to relate to the master's, and gpg accepts an RSA encryption subkey under a DSA primary key.
        /// </para>
        /// </summary>
        /// <param name="strength">Key strength in bits (used by RSA).</param>
        /// <param name="certainty">Primality certainty (used by RSA).</param>
        /// <exception cref="NotSupportedException">Thrown when the configured algorithm has no supported encryption pairing.</exception>
        private PgpKeyPair GenerateEncryptionSubKeyPair(int strength, int certainty)
        {
            DateTime creationTime = DateTime.UtcNow;
            SecureRandom secureRandom = new SecureRandom();

            switch (PublicKeyAlgorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.Dsa:
                {
                    // RsaGeneral rather than RsaEncrypt: it is what gpg emits for RSA encryption subkeys,
                    // and RsaEncrypt is deprecated by RFC 4880.
                    IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
                    kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), secureRandom, strength, certainty));
                    return new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kpg.GenerateKeyPair(), creationTime);
                }

                case PublicKeyAlgorithmTag.EdDsa:
                {
                    // X25519 ECDH, the encryption subkey gpg pairs with an Ed25519 master.
                    X25519KeyPairGenerator kpg = new X25519KeyPairGenerator();
                    kpg.Init(new X25519KeyGenerationParameters(secureRandom));
                    return new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, kpg.GenerateKeyPair(), creationTime);
                }

                case PublicKeyAlgorithmTag.ECDsa:
                {
                    // ECDH on the same named curve as the ECDSA master.
                    ECKeyPairGenerator kpg = new ECKeyPairGenerator("ECDH");
                    kpg.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, secureRandom));
                    return new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, kpg.GenerateKeyPair(), creationTime);
                }

                default:
                    throw new NotSupportedException(
                        $"No encryption subkey pairing is defined for {PublicKeyAlgorithm}.");
            }
        }

        /// <summary>
        /// Generates DSA key material. BouncyCastle's legacy parameter generator only accepts 512-1024 bit
        /// keys in 64 bit steps, so a larger strength previously surfaced as a raw BouncyCastle
        /// "size must be from 512 - 1024 and a multiple of 64" error - including at the library's own
        /// default strength (GitHub issue #285). Larger keys go through the FIPS 186-3 generator instead.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the strength cannot produce a valid DSA key.</exception>
        private static AsymmetricCipherKeyPair GenerateDsaKeyPair(int strength, int certainty, SecureRandom secureRandom)
        {
            if (strength < MinimumDsaStrength)
                throw new ArgumentOutOfRangeException(nameof(strength), strength,
                    $"DSA keys must be at least {MinimumDsaStrength} bits.");

            DsaParametersGenerator parametersGenerator;

            if (strength <= MaximumLegacyDsaStrength)
            {
                if (strength % 64 != 0)
                    throw new ArgumentOutOfRangeException(nameof(strength), strength,
                        $"DSA keys of {MinimumDsaStrength} to {MaximumLegacyDsaStrength} bits must be a multiple of 64.");

                parametersGenerator = new DsaParametersGenerator();
                parametersGenerator.Init(strength, certainty, secureRandom);
            }
            else
            {
                // A 256 bit subgroup needs a digest of at least the same size.
                parametersGenerator = new DsaParametersGenerator(new Sha256Digest());
                parametersGenerator.Init(
                    new DsaParameterGenerationParameters(strength, LargeDsaSubgroupSize, certainty, secureRandom));
            }

            DsaKeyPairGenerator keyPairGenerator = new DsaKeyPairGenerator();
            keyPairGenerator.Init(new DsaKeyGenerationParameters(secureRandom, parametersGenerator.GenerateParameters()));
            return keyPairGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// Returns the hash algorithm to use for the master key's self-certification.
        /// EdDSA and ECDSA signatures require SHA-256 or stronger; SHA-1 produces an invalid key/signing failure.
        /// The same applies to DSA keys large enough to use a 256 bit subgroup, where SHA-1 is too short.
        /// For those algorithms this promotes a SHA-1 certification hash to SHA-256, while leaving RSA (and any
        /// explicitly requested stronger hash) untouched.
        /// </summary>
        private HashAlgorithmTag GetCertificationHashAlgorithm(HashAlgorithmTag requestedHash, int strength)
        {
            bool requiresStrongHash =
                PublicKeyAlgorithm == PublicKeyAlgorithmTag.EdDsa ||
                PublicKeyAlgorithm == PublicKeyAlgorithmTag.ECDsa ||
                (PublicKeyAlgorithm == PublicKeyAlgorithmTag.Dsa && strength > MaximumLegacyDsaStrength);

            if (requiresStrongHash && requestedHash == HashAlgorithmTag.Sha1)
                return HashAlgorithmTag.Sha256;

            return requestedHash;
        }
    }
}
