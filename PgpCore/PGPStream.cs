using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PgpCore
{
    public class PGPStream : Stream, IDisposable
    {
        public enum PGPMode { Encrypt, Decrypt }

        private readonly PGPMode Mode;
        private readonly PGP.PGPOutputContext Context;
        private readonly Stream OutputStream;
        internal PGPStream(Stream inputStream, IEncryptionKeys encryptionKeys, PGPMode pgpMode)
        {
            this.Mode = pgpMode;
            switch (pgpMode)
            {
                case PGPMode.Encrypt:
                    break;
                case PGPMode.Decrypt:
                    this.Context = PGP.Decrypt(encryptionKeys, inputStream);
                    OutputStream = this.Context.OutputStream;
                    break;
                default:
                    break;
            }
        }

        public override bool CanRead => OutputStream.CanRead;

        public override bool CanSeek => OutputStream.CanSeek;

        public override bool CanWrite => OutputStream.CanWrite;

        public override long Length => OutputStream.Length;

        public override long Position { get => OutputStream.Position; set => OutputStream.Position = value; }

        public new void Dispose()
        {
            OutputStream.Dispose();
        }

        public override void Flush()
        {
            OutputStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int result = OutputStream.Read(buffer, offset, count);
            if (this.Position == this.Length && this.Mode == PGPMode.Decrypt)
                this.Context.VerifyIntegrity();
            return result;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return OutputStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            OutputStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            OutputStream.Write(buffer, offset, count);
        }
    }
}
