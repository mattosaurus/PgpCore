using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCore
{
    public class PgpPublicKeyRingWithPreferredKey
    {
        public PgpPublicKeyRing PgpPublicKeyRing { get; set; }
        public PgpPublicKey PreferredKey { get; private set; } = null;

        public PgpPublicKeyRingWithPreferredKey(PgpPublicKeyRing publicKeyRing)
        {
            PgpPublicKeyRing = publicKeyRing;
        }
        
        public PgpPublicKeyRingWithPreferredKey(PgpPublicKeyRing publicKeyRing, long preferredKeyId)
        {
            PgpPublicKeyRing = publicKeyRing;
            UseEncryptionKey(preferredKeyId);
        }

        /// <summary>
        /// This method will try to find the key with the given keyId and set it as the preferred key.
        /// If it cannot find the key, it will not change the preferred key.
        /// </summary>
        /// <param name="keyId">The keyId to find.</param>
        public void UseEncryptionKey(long keyId)
        {
            PreferredKey = PgpPublicKeyRing.GetPublicKeys().FirstOrDefault(key => key.KeyId == keyId && key.IsEncryptionKey) ?? PreferredKey;
        }
    }
}