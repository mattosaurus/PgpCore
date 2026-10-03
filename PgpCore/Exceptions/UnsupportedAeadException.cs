using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when the message uses an AEAD session-key format that PgpCore cannot decrypt.
    /// BouncyCastle may recognize the packets without implementing their decryption.
    /// See https://github.com/mattosaurus/PgpCore/issues/219.
    /// </summary>
    public class UnsupportedAeadException : PgpCoreException
    {
        public UnsupportedAeadException(string message) : base(message)
        {
        }

        public UnsupportedAeadException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
