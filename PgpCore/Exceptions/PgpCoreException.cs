using System;

namespace PgpCore
{
    /// <summary>
    /// Base exception for all errors raised by PgpCore.
    /// </summary>
    public class PgpCoreException : Exception
    {
        public PgpCoreException(string message) : base(message)
        {
        }

        public PgpCoreException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
