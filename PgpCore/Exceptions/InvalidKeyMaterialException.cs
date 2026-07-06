using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when supplied key material could not be parsed as a valid OpenPGP key or keyring.
    /// </summary>
    public class InvalidKeyMaterialException : PgpCoreException
    {
        public InvalidKeyMaterialException(string message) : base(message)
        {
        }

        public InvalidKeyMaterialException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
