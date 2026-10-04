using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;

namespace PgpCore.Helpers
{
    /// <summary>Checks encrypted packet formats before the legacy CFB reader can misinterpret AEAD data.</summary>
    internal static class PgpPacketReader
    {
        internal static PgpObjectFactory CreateFactory(Stream decoded)
        {
            int first = decoded.ReadByte();
            if (first < 0) return new PgpObjectFactory(Stream.Null);
            Stream replay = new PrefixStream(new[] { (byte)first }, decoded);
            // NextPacketTag assumes a binary packet header. Clear-signed text is
            // readable from the armor stream too; its characters are not packet tags.
            if ((first & 0x80) == 0) return new PgpObjectFactory(replay);
            var packets = new BcpgInputStream(replay);
            using var prefix = new MemoryStream();
            var encoded = new BcpgOutputStream(prefix);
            PacketTag tag = packets.NextPacketTag();
            while (tag == PacketTag.Marker || tag == PacketTag.PublicKeyEncryptedSession ||
                tag == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                // Use BouncyCastle's parser and encoder for recipient packets. Only these small
                // headers are replayed; payloads stay streaming, including non-seekable inputs.
                var packet = (ContainedPacket)packets.ReadPacket();
                if (packet is SymmetricKeyEncSessionPacket password && password.Version >= 5)
                    throw new UnsupportedAeadException("AEAD encrypted messages with session-key packet version " + password.Version +
                        " are not supported. Ask the sender for non-AEAD output. See https://github.com/mattosaurus/PgpCore/issues/219.");
                packet.Encode(encoded);
                tag = packets.NextPacketTag();
            }
            if (tag == PacketTag.AeadEncData)
                throw new UnsupportedAeadException("The message uses AEAD (OCB) encryption (packet tag 20), which the referenced BouncyCastle version cannot decrypt. " +
                    "Ask the sender for non-AEAD, MDC-protected output. See https://github.com/mattosaurus/PgpCore/issues/219.");
            encoded.Flush();
            return new PgpObjectFactory(prefix.Length == 0 ? packets : new PrefixStream(prefix.ToArray(), packets));
        }

        private sealed class PrefixStream : Stream
        {
            private readonly byte[] _prefix;
            private readonly Stream _source;
            private int _position;
            internal PrefixStream(byte[] prefix, Stream source) { _prefix = prefix; _source = source; }
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override int Read(byte[] buffer, int offset, int count)
            {
                if (buffer == null) throw new ArgumentNullException(nameof(buffer));
                if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException();
                int copied = Math.Min(count, _prefix.Length - _position);
                if (copied == 0) return _source.Read(buffer, offset, count);
                Array.Copy(_prefix, _position, buffer, offset, copied);
                _position += copied;
                return copied;
            }
            public override int ReadByte() => _position < _prefix.Length ? _prefix[_position++] : _source.ReadByte();
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            // The caller owns the decoded input stream.
        }
    }
}
