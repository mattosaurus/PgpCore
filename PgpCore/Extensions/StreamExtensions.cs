using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Extensions
{
    internal static class StreamExtensions
    {
        internal static string GetString(this Stream inputStream, Encoding encoding = null)
        {
            var reader = encoding != null ? new StreamReader(inputStream, encoding) : new StreamReader(inputStream);
            var output = reader.ReadToEnd();
            return output;
        }

        internal static async Task<string> GetStringAsync(this Stream inputStream, Encoding encoding = null)
        {
            var reader = encoding != null ? new StreamReader(inputStream, encoding) : new StreamReader(inputStream);
            var output = await reader.ReadToEndAsync().ConfigureAwait(false);
            return output;
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
