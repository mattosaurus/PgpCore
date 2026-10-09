using Org.BouncyCastle.Bcpg;
using System;

namespace PgpCore.Models
{
    /// <summary>Public certificate metadata derived from authenticated self-signatures and bindings.</summary>
    public sealed class PgpKeyInfo
    {
        /// <summary>The key ID as sixteen uppercase hexadecimal digits without a prefix.</summary>
        public string KeyId { get; internal set; }
        /// <summary>The full hexadecimal fingerprint of this key.</summary>
        public string Fingerprint { get; internal set; }
        /// <summary>The primary fingerprint identifying this certificate; applications establish its trust.</summary>
        public string PrimaryFingerprint { get; internal set; }
        /// <summary>Self-certified user identifiers carried by the primary key; these are not external identity proof.</summary>
        public string[] UserIds { get; internal set; }
        /// <summary>The public key algorithm.</summary>
        public PublicKeyAlgorithmTag Algorithm { get; internal set; }
        /// <summary>The algorithm-specific key strength.</summary>
        public int BitStrength { get; internal set; }
        /// <summary>The key creation time in UTC.</summary>
        public DateTime CreationTime { get; internal set; }
        /// <summary>The expiry declared by the authenticated authorization, if any.</summary>
        public DateTime? Expiration { get; internal set; }
        /// <summary>Whether this is the primary key.</summary>
        public bool IsMasterKey { get; internal set; }
        /// <summary>Whether the algorithm supports encryption, independently of authorization.</summary>
        public bool IsEncryptionKey { get; internal set; }
        /// <summary>Whether a valid primary-issued revocation affects this key.</summary>
        public bool IsRevoked { get; internal set; }
        /// <summary>Whether authenticated flags and bindings authorize signing.</summary>
        public bool CanSign { get; internal set; }
        /// <summary>Whether authenticated flags and bindings authorize encryption.</summary>
        public bool CanEncrypt { get; internal set; }
        /// <summary>Whether this key and its primary are current and authorize new signatures.</summary>
        public bool IsUsableForSigning { get; internal set; }
        /// <summary>Whether this key and its primary are current and authorize encryption.</summary>
        public bool IsUsableForEncryption { get; internal set; }
    }
}
