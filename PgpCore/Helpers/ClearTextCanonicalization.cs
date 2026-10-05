using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Text;

namespace PgpCore.Helpers
{
    /// <summary>Canonicalizes clear-signed text without retaining a whole line in memory.</summary>
    internal static class ClearTextCanonicalization
    {
        internal static bool Copy(ArmoredInputStream input, Stream output)
        {
            if (!input.IsClearText())
                throw new InvalidDataException("Expected a clear-signed message.");
            byte[] buffer = new byte[16384];
            byte[] separator = Encoding.ASCII.GetBytes(Environment.NewLine);
            int character = input.ReadByte();
            bool singleLine = true;
            while (character >= 0 && input.IsClearText())
            {
                long start = output.Position;
                if (start > 0) singleLine = false;
                long length = 0, trimmedLength = 0;
                int count = 0;
                while (character >= 0 && character != '\r' && character != '\n')
                {
                    buffer[count++] = (byte)character;
                    length++;
                    if (character != ' ' && character != '\t') trimmedLength = length;
                    if (count == buffer.Length)
                    {
                        output.Write(buffer, 0, count);
                        count = 0;
                    }
                    character = input.ReadByte();
                }
                if (count > 0) output.Write(buffer, 0, count);
                // Discard trailing spaces/tabs on disk, including runs spanning buffers.
                if (trimmedLength != length)
                {
                    output.SetLength(start + trimmedLength);
                    output.Position = start + trimmedLength;
                }
                output.Write(separator, 0, separator.Length);

                int ending = character;
                character = input.ReadByte();
                if (ending == '\r' && character == '\n') character = input.ReadByte();
                // The armor reader consumes the start of the signature marker and
                // changes IsClearText. Leave its binary packet reader positioned there.
            }
            return singleLine;
        }

        internal static void UpdateSignature(PgpSignature signature, Stream clearText)
        {
            clearText.Position = 0;
            // The separator immediately before the signature armor is not signed.
            long remaining = Math.Max(0, clearText.Length - Environment.NewLine.Length);
            byte[] buffer = new byte[16384];
            while (remaining > 0)
            {
                int count = clearText.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (count == 0) throw new EndOfStreamException();
                remaining -= count;
                if (Environment.NewLine == "\r\n")
                    signature.Update(buffer, 0, count);
                else
                {
                    int start = 0;
                    for (int i = 0; i < count; i++)
                    {
                        if (buffer[i] != '\n') continue;
                        if (i > start) signature.Update(buffer, start, i - start);
                        signature.Update((byte)'\r');
                        signature.Update((byte)'\n');
                        start = i + 1;
                    }
                    if (start < count) signature.Update(buffer, start, count - start);
                }
            }
        }
    }
}
