using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCore
{
    /// <summary>
    /// A wrapper class for <see cref="PgpPublicKeyRing"/> that also keeps track of a preferred <see cref="PgpPublicKey"/> to be used for encryption.
    /// </summary>
    public class PgpPublicKeyRingWithPreferredKey
    {
        public PgpPublicKeyRing PgpPublicKeyRing { get; set; }
        public PgpPublicKey PreferredEncryptionKey { get; private set; } = null;
        public PgpPublicKey DefaultEncryptionKey => _defaultEncryptionKey.Value;

        private Lazy<PgpPublicKey> _defaultEncryptionKey;
        private Lazy<IEnumerable<PgpPublicKey>> _encryptionKeys;

        public PgpPublicKeyRingWithPreferredKey(PgpPublicKeyRing publicKeyRing)
        {
            PgpPublicKeyRing = publicKeyRing;
            _defaultEncryptionKey = new Lazy<PgpPublicKey>(() => Utilities.FindBestEncryptionKey(PgpPublicKeyRing));
            _encryptionKeys = new Lazy<IEnumerable<PgpPublicKey>>(() => PgpPublicKeyRing.GetPublicKeys().Where(key => key.IsEncryptionKey));
        }

        /// <summary>
        /// Try to find the key with the given keyId and set it as the preferred encryption key.
        /// If no key is found, the preferred key is not changed.
        /// </summary>
        /// <param name="keyId">The keyId to find.</param>
        public void UsePreferredEncryptionKey(long? keyId)
        {
            PreferredEncryptionKey = _encryptionKeys.Value.FirstOrDefault(key => key.KeyId == keyId) ?? PreferredEncryptionKey;
        }

        /// <summary>
        /// Clear the preferred encryption key.
        /// </summary>
        public void ClearPreferredEncryptionKey()
        {
            PreferredEncryptionKey = null;
        }
    }
}