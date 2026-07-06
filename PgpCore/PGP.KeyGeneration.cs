using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;

namespace PgpCore
{
    public partial class PGP
    {
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
                {
                    DsaParametersGenerator paramsGen = new DsaParametersGenerator();
                    paramsGen.Init(strength, certainty, secureRandom);
                    DsaKeyGenerationParameters keyGenParams = new DsaKeyGenerationParameters(secureRandom, paramsGen.GenerateParameters());
                    DsaKeyPairGenerator kpg = new DsaKeyPairGenerator();
                    kpg.Init(keyGenParams);
                    return new PgpKeyPair(PublicKeyAlgorithmTag.Dsa, kpg.GenerateKeyPair(), creationTime);
                }

                default:
                    throw new NotSupportedException(
                        $"Key generation for {PublicKeyAlgorithm} is not supported. " +
                        "Supported algorithms are RsaGeneral/RsaSign/RsaEncrypt, EdDsa (Ed25519), ECDsa (NIST P-256) and Dsa.");
            }
        }

        /// <summary>
        /// Returns the hash algorithm to use for the master key's self-certification.
        /// EdDSA and ECDSA signatures require SHA-256 or stronger; SHA-1 produces an invalid key/signing failure.
        /// For those algorithms this promotes a SHA-1 certification hash to SHA-256, while leaving RSA (and any
        /// explicitly requested stronger hash) untouched.
        /// </summary>
        private HashAlgorithmTag GetCertificationHashAlgorithm(HashAlgorithmTag requestedHash)
        {
            bool requiresStrongHash =
                PublicKeyAlgorithm == PublicKeyAlgorithmTag.EdDsa ||
                PublicKeyAlgorithm == PublicKeyAlgorithmTag.ECDsa;

            if (requiresStrongHash && requestedHash == HashAlgorithmTag.Sha1)
                return HashAlgorithmTag.Sha256;

            return requestedHash;
        }
    }
}
