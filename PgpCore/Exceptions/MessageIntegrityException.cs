using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when a decrypted message fails its modification detection (MDC) integrity check,
    /// indicating the ciphertext may have been tampered with.
    /// </summary>
    public class MessageIntegrityException : PgpCoreException
    {
        public MessageIntegrityException(string message) : base(message)
        {
        }

        public MessageIntegrityException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
