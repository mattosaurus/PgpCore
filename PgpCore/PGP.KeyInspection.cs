using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PgpCore
{
    public partial class PGP
    {
        /// <summary>
        /// Reads every primary and subkey in public or private key material, authenticating certificate
        /// bindings and metadata. The caller retains ownership of the input stream. Fingerprints must
        /// still be checked against the application's independently trusted identity.
        /// </summary>
        /// <param name="keyStream">Public or private certificate data at its current stream position.</param>
        /// <returns>One metadata record per key, with each primary followed by its subkeys.</returns>
        /// <exception cref="InvalidKeyMaterialException">When no certificate is present or a binding is invalid.</exception>
        public static IReadOnlyList<PgpKeyInfo> InspectKeys(Stream keyStream)
        {
            if (keyStream == null) throw new ArgumentNullException(nameof(keyStream));
            var result = new List<PgpKeyInfo>();
            foreach (var ring in Utilities.ReadAllKeyRings(keyStream))
            {
                KeyRingValidation.Key[] keys = KeyRingValidation.Read(ring);
                string primaryFingerprint = Hex(keys[0].PublicKey.GetFingerprint());
                string[] userIds = KeyRingValidation.UserIds(keys[0].PublicKey);
                DateTime now = DateTime.UtcNow;
                bool primaryCurrent = keys[0].IsCurrent(now);
                foreach (var key in keys)
                {
                    long seconds = key.ExpirationSeconds;
                    DateTime? expiration = seconds <= 0 || seconds > (DateTime.MaxValue - key.PublicKey.CreationTime).TotalSeconds
                        ? (DateTime?)null : key.PublicKey.CreationTime.AddSeconds(seconds);
                    result.Add(new PgpKeyInfo
                    {
                        KeyId = $"0x{unchecked((ulong)key.PublicKey.KeyId):X16}",
                        Fingerprint = Hex(key.PublicKey.GetFingerprint()),
                        PrimaryFingerprint = primaryFingerprint,
                        UserIds = userIds.ToArray(),
                        Algorithm = key.PublicKey.Algorithm,
                        BitStrength = key.PublicKey.BitStrength,
                        CreationTime = key.PublicKey.CreationTime,
                        Expiration = expiration,
                        IsMasterKey = key.PublicKey.IsMasterKey,
                        IsEncryptionKey = key.PublicKey.IsEncryptionKey,
                        IsRevoked = key.Revoked,
                        CanSign = key.CanSign,
                        CanEncrypt = key.CanEncrypt,
                        IsUsableForSigning = key.CanSign && primaryCurrent && key.IsCurrent(now),
                        IsUsableForEncryption = key.CanEncrypt && primaryCurrent && key.IsCurrent(now)
                    });
                }
            }
            if (result.Count == 0) throw new InvalidKeyMaterialException("No PGP certificate found in key material.");
            return result;
        }

        private static string Hex(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", string.Empty);
    }
}
