using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when an operation requires a key that was not supplied in the <see cref="EncryptionKeys"/>.
    /// </summary>
    public class MissingKeyException : PgpCoreException
    {
        public MissingKeyException(string message) : base(message)
        {
        }

        public MissingKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// Thrown when no key suitable for encryption could be found in the supplied public key material.
    /// </summary>
    public class NoEncryptionKeyException : MissingKeyException
    {
        public NoEncryptionKeyException(string message) : base(message)
        {
        }

        public NoEncryptionKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// Thrown when no key suitable for signing could be found in the supplied private key material.
    /// </summary>
    public class NoSigningKeyException : MissingKeyException
    {
        public NoSigningKeyException(string message) : base(message)
        {
        }

        public NoSigningKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// Thrown when a message could not be decrypted because none of the supplied private keys match
    /// any of the keys the message was encrypted to.
    /// </summary>
    public class NoDecryptionKeyException : MissingKeyException
    {
        public NoDecryptionKeyException(string message) : base(message)
        {
        }

        public NoDecryptionKeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
