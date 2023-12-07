using System;
using System.Collections.Generic;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Models;

namespace PgpCore.Abstractions
{
    /// <summary>
    /// Encryption Keys
    /// 
    /// You can supply any or all of these, however, if PrivateKeys 
    /// are required Secret keys should also be supplied
    /// </summary>
    public interface IEncryptionKeys
    {
        IEnumerable<PgpPublicKeyRingWithPreferredKey> PublicKeyRings { get; }
        IEnumerable<PgpPublicKey> EncryptKeys { get; }
        IEnumerable<PgpPublicKey> VerificationKeys { get; }
        PgpPrivateKey SigningPrivateKey { get; }
        PgpSecretKey SigningSecretKey { get; }
        PgpPublicKey MasterKey { get; }
        [Obsolete("This property is obsolete and will be removed in a future release. Use the MasterKey or EncryptKeys.FirstOrDefault() properties instead.")]
        PgpPublicKey PublicKey { get; }
        [Obsolete("This property is obsolete and will be removed in a future release. Use the MasterKey and EncryptKeys properties instead.")]
        IEnumerable<PgpPublicKey> PublicKeys { get; }
        PgpPrivateKey PrivateKey { get; }
        PgpSecretKey SecretKey { get; }
        PgpSecretKeyRingBundle SecretKeys { get; }

        PgpPrivateKey FindSecretKey(long keyId);
    }
}