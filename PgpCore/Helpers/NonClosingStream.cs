using System.IO;

namespace PgpCore.Helpers
{
    /// <summary>Allows packet readers and writers to finalize without closing a borrowed stream.</summary>
    internal sealed class NonClosingStream : Org.BouncyCastle.Utilities.IO.FilterStream
    {
        internal NonClosingStream(Stream stream) : base(stream) { }
        protected override void Dispose(bool disposing)
        {
            if (disposing && CanWrite)
                Flush();
        }
    }
}
