using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Extensions;
using PgpCore.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PgpCore
{
    /// <summary>
    /// Fluent builder for <see cref="EncryptionKeys"/>. Use it when you need to combine
    /// multiple public keys, supply more than one private key (each with its own passphrase),
    /// or nominate a specific encryption key by id instead of letting the library pick the
    /// "best" key automatically.
    /// </summary>
    /// <example>
    /// <code>
    /// EncryptionKeys keys = new EncryptionKeysBuilder()
    ///     .WithPublicKey(recipientPublicKey)
    ///     .WithPrivateKey(myPrivateKeyFile, "my-passphrase")
    ///     .WithPrivateKey(secondPrivateKeyFile, "other-passphrase")
    ///     .WithPreferredEncryptionKeyId(0x1234ABCD)
    ///     .Build();
    /// </code>
    /// </example>
    public class EncryptionKeysBuilder
    {
        private readonly List<Func<Stream>> _publicKeySources = new List<Func<Stream>>();
        private readonly List<KeyValuePair<Func<Stream>, byte[]>> _privateKeySources = new List<KeyValuePair<Func<Stream>, byte[]>>();
        private byte[] _symmetricKey;
        private long? _preferredEncryptionKeyId;

        #region Public keys

        public EncryptionKeysBuilder WithPublicKey(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException($"{nameof(publicKey)} cannot be null or empty.", nameof(publicKey));
            _publicKeySources.Add(() => publicKey.GetStream());
            return this;
        }

        public EncryptionKeysBuilder WithPublicKey(FileInfo publicKeyFile)
        {
            if (publicKeyFile == null)
                throw new ArgumentNullException(nameof(publicKeyFile));
            if (!publicKeyFile.Exists)
                throw new FileNotFoundException($"Public Key file [{publicKeyFile.FullName}] does not exist.");
            _publicKeySources.Add(() => publicKeyFile.OpenRead());
            return this;
        }

        public EncryptionKeysBuilder WithPublicKey(Stream publicKeyStream)
        {
            if (publicKeyStream == null)
                throw new ArgumentNullException(nameof(publicKeyStream));
            _publicKeySources.Add(() => publicKeyStream);
            return this;
        }

        #endregion Public keys

        #region Private keys

        public EncryptionKeysBuilder WithPrivateKey(string privateKey, string passPhrase = null)
        {
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException($"{nameof(privateKey)} cannot be null or empty.", nameof(privateKey));
            _privateKeySources.Add(new KeyValuePair<Func<Stream>, byte[]>(() => privateKey.GetStream(), ToRawPassPhrase(passPhrase)));
            return this;
        }

        public EncryptionKeysBuilder WithPrivateKey(FileInfo privateKeyFile, string passPhrase = null)
        {
            if (privateKeyFile == null)
                throw new ArgumentNullException(nameof(privateKeyFile));
            if (!privateKeyFile.Exists)
                throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");
            _privateKeySources.Add(new KeyValuePair<Func<Stream>, byte[]>(() => privateKeyFile.OpenRead(), ToRawPassPhrase(passPhrase)));
            return this;
        }

        public EncryptionKeysBuilder WithPrivateKey(Stream privateKeyStream, string passPhrase = null)
        {
            if (privateKeyStream == null)
                throw new ArgumentNullException(nameof(privateKeyStream));
            _privateKeySources.Add(new KeyValuePair<Func<Stream>, byte[]>(() => privateKeyStream, ToRawPassPhrase(passPhrase)));
            return this;
        }

        #endregion Private keys

        /// <summary>
        /// Sets an optional symmetric key for password-based (PBE) encryption/decryption.
        /// </summary>
        public EncryptionKeysBuilder WithSymmetricKey(byte[] symmetricKey)
        {
            _symmetricKey = symmetricKey;
            return this;
        }

        /// <summary>
        /// Nominates the encryption key to use by id, overriding automatic "best key" selection.
        /// </summary>
        public EncryptionKeysBuilder WithPreferredEncryptionKeyId(long keyId)
        {
            _preferredEncryptionKeyId = keyId;
            return this;
        }

        /// <summary>
        /// Builds the <see cref="EncryptionKeys"/> from the configured sources.
        /// </summary>
        public EncryptionKeys Build()
        {
            if (_publicKeySources.Count == 0 && _privateKeySources.Count == 0 && (_symmetricKey == null || _symmetricKey.Length == 0))
                throw new InvalidKeyMaterialException("No keys supplied. Provide at least one public key, private key, or symmetric key.");

            List<PgpPublicKeyRing> publicKeyRings = new List<PgpPublicKeyRing>();
            foreach (Func<Stream> source in _publicKeySources)
            {
                using (Stream stream = source())
                    publicKeyRings.AddRange(Utilities.ReadAllKeyRings(stream));
            }

            List<PgpSecretKeyRing> secretKeyRings = new List<PgpSecretKeyRing>();
            Dictionary<long, byte[]> passPhrasesByKeyId = new Dictionary<long, byte[]>();
            byte[] fallbackPassPhrase = null;

            foreach (KeyValuePair<Func<Stream>, byte[]> source in _privateKeySources)
            {
                PgpSecretKeyRingBundle bundle;
                using (Stream stream = source.Key())
                    bundle = Utilities.ReadSecretKeyRingBundle(stream);

                fallbackPassPhrase = fallbackPassPhrase ?? source.Value;

                foreach (PgpSecretKeyRing ring in bundle.GetKeyRings().Cast<PgpSecretKeyRing>())
                {
                    secretKeyRings.Add(ring);
                    foreach (PgpSecretKey secretKey in ring.GetSecretKeys().Cast<PgpSecretKey>())
                        passPhrasesByKeyId[secretKey.KeyId] = source.Value;
                }
            }

            PgpSecretKeyRingBundle secretKeys = secretKeyRings.Count > 0
                ? new PgpSecretKeyRingBundle(secretKeyRings)
                : null;

            byte[] resolverFallback = fallbackPassPhrase;
            Func<long, byte[]> passPhraseResolver = secretKeys == null
                ? (Func<long, byte[]>)null
                : keyId => passPhrasesByKeyId.TryGetValue(keyId, out byte[] pass) ? pass : resolverFallback;

            return new EncryptionKeys(publicKeyRings, secretKeys, passPhraseResolver, _symmetricKey, _preferredEncryptionKeyId);
        }

        private static byte[] ToRawPassPhrase(string passPhrase) =>
            Encoding.UTF8.GetBytes(passPhrase ?? string.Empty);
    }
}
