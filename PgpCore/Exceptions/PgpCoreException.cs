using System;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCore
{
    /// <summary>
    /// Base exception for all errors raised by PgpCore.
    /// Derives from <see cref="PgpException"/> so existing code catching the BouncyCastle
    /// exception type continues to work; this inheritance will change to <see cref="Exception"/>
    /// in the next major version.
    /// </summary>
    public class PgpCoreException : PgpException
    {
        public PgpCoreException(string message) : base(message)
        {
        }

        public PgpCoreException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
