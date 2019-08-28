using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public sealed class Streams
    {
        private const int BufferSize = 512;

        private Streams()
        {
        }

        public static void Drain(Stream inStr)
        {
            byte[] bs = new byte[BufferSize];
            while (inStr.Read(bs, 0, bs.Length) > 0)
            {
            }
        }

        public static byte[] ReadAll(Stream inStr)
        {
            MemoryStream buf = new MemoryStream();
            PipeAll(inStr, buf);
            return buf.ToArray();
        }

        public static byte[] ReadAllLimited(Stream inStr, int limit)
        {
            MemoryStream buf = new MemoryStream();
            PipeAllLimited(inStr, limit, buf);
            return buf.ToArray();
        }

        public static int ReadFully(Stream inStr, byte[] buf)
        {
            return ReadFully(inStr, buf, 0, buf.Length);
        }

        public static int ReadFully(Stream inStr, byte[] buf, int off, int len)
        {
            int totalRead = 0;
            while (totalRead < len)
            {
                int numRead = inStr.Read(buf, off + totalRead, len - totalRead);
                if (numRead < 1)
                    break;
                totalRead += numRead;
            }
            return totalRead;
        }

        public static void PipeAll(Stream inStr, Stream outStr)
        {
            byte[] bs = new byte[BufferSize];
            int numRead;
            while ((numRead = inStr.Read(bs, 0, bs.Length)) > 0)
            {
                outStr.Write(bs, 0, numRead);
            }
        }

        /// <summary>
        /// Pipe all bytes from <c>inStr</c> to <c>outStr</c>, throwing <c>StreamFlowException</c> if greater
        /// than <c>limit</c> bytes in <c>inStr</c>.
        /// </summary>
        /// <param name="inStr">
        /// A <see cref="Stream"/>
        /// </param>
        /// <param name="limit">
        /// A <see cref="System.Int64"/>
        /// </param>
        /// <param name="outStr">
        /// A <see cref="Stream"/>
        /// </param>
        /// <returns>The number of bytes actually transferred, if not greater than <c>limit</c></returns>
        /// <exception cref="IOException"></exception>
        public static long PipeAllLimited(Stream inStr, long limit, Stream outStr)
        {
            byte[] bs = new byte[BufferSize];
            long total = 0;
            int numRead;
            while ((numRead = inStr.Read(bs, 0, bs.Length)) > 0)
            {
                if ((limit - total) < numRead)
                    throw new StreamOverflowException("Data Overflow");
                total += numRead;
                outStr.Write(bs, 0, numRead);
            }
            return total;
        }

        /// <exception cref="IOException"></exception>
        public static void WriteBufTo(MemoryStream buf, Stream output)
        {
            buf.WriteTo(output);
        }

        public static async Task DrainAsync(Stream inStr)
        {
            byte[] bs = new byte[BufferSize];
            while (await inStr.ReadAsync(bs, 0, bs.Length) > 0)
            {
            }
        }

        public static async Task<byte[]> ReadAllAsync(Stream inStr)
        {
            MemoryStream buf = new MemoryStream();
            await PipeAllAsync(inStr, buf);
            return buf.ToArray();
        }

        public static async Task<byte[]> ReadAllLimitedAsync(Stream inStr, int limit)
        {
            MemoryStream buf = new MemoryStream();
            await PipeAllLimitedAsync(inStr, limit, buf);
            return buf.ToArray();
        }

        public static async Task<int> ReadFullyAsync(Stream inStr, byte[] buf)
        {
            return await ReadFullyAsync(inStr, buf, 0, buf.Length);
        }

        public static async Task<int> ReadFullyAsync(Stream inStr, byte[] buf, int off, int len)
        {
            int totalRead = 0;
            while (totalRead < len)
            {
                int numRead = await inStr.ReadAsync(buf, off + totalRead, len - totalRead);
                if (numRead < 1)
                    break;
                totalRead += numRead;
            }
            return totalRead;
        }

        public static async Task PipeAllAsync(Stream inStr, Stream outStr)
        {
            byte[] bs = new byte[BufferSize];
            int numRead;
            while ((numRead = await inStr.ReadAsync(bs, 0, bs.Length)) > 0)
            {
                await outStr.WriteAsync(bs, 0, numRead);
            }
        }

        public static async Task<long> PipeAllLimitedAsync(Stream inStr, long limit, Stream outStr)
        {
            byte[] bs = new byte[BufferSize];
            long total = 0;
            int numRead;
            while ((numRead = await inStr.ReadAsync(bs, 0, bs.Length)) > 0)
            {
                if ((limit - total) < numRead)
                    throw new StreamOverflowException("Data Overflow");
                total += numRead;
                await outStr.WriteAsync(bs, 0, numRead);
            }
            return total;
        }
    }
}
