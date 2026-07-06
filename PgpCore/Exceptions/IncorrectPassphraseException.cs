using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when a private key cannot be unlocked because the supplied passphrase is incorrect.
    /// </summary>
    public class IncorrectPassphraseException : PgpCoreException
    {
        public IncorrectPassphraseException(string message) : base(message)
        {
        }

        public IncorrectPassphraseException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
