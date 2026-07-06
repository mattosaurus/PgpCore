using System;

namespace PgpCore
{
    /// <summary>
    /// Thrown when data passed to a decrypt operation is not encrypted — for example plain text,
    /// a signed-only message, or a clear-signed message.
    /// </summary>
    public class NotEncryptedDataException : PgpCoreException
    {
        public NotEncryptedDataException(string message) : base(message)
        {
        }

        public NotEncryptedDataException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
