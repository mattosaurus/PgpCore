using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when the input is an AEAD (OCB) encrypted message. These messages use the AEAD encrypted
    /// data packet, tag 20, which the underlying BouncyCastle version cannot read - it rejects the packet
    /// before PgpCore sees it. See https://github.com/mattosaurus/PgpCore/issues/219 for the current
    /// status and the workaround of removing the AEAD feature flag from the key.
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
