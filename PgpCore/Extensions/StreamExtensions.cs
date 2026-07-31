using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Extensions
{
    internal static class StreamExtensions
    {
        // The readers below are disposed with leaveOpen: true - the stream belongs to the caller,
        // which continues using and disposing it. Encoding, BOM detection and buffer size match
        // StreamReader's defaults so behaviour is unchanged.

        internal static string GetString(this Stream inputStream, Encoding encoding = null)
        {
            using (var reader = new StreamReader(inputStream, encoding ?? Encoding.UTF8,
                       detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true))
            {
                return reader.ReadToEnd();
            }
        }

        internal static async Task<string> GetStringAsync(this Stream inputStream, Encoding encoding = null)
        {
            using (var reader = new StreamReader(inputStream, encoding ?? Encoding.UTF8,
                       detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true))
            {
                return await reader.ReadToEndAsync().ConfigureAwait(false);
            }
        }

        internal static Encoding GetEncoding(this Stream inputStream)
        {
            Encoding defaultEncodingIfNoBom = Encoding.UTF8;

            using (var reader = new StreamReader(inputStream, defaultEncodingIfNoBom, true, 1024, true))
            {
                reader.Peek();
                return reader.CurrentEncoding;
            }
        }
    }
}
