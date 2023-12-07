using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Extensions
{
    internal static class StringExtensions
    {
        public static Stream GetStream(this string s, Encoding encoding = null)
        {
            var stream = new MemoryStream();
            var writer = encoding != null ? new StreamWriter(stream, encoding) : new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static async Task<Stream> GetStreamAsync(this string s, Encoding encoding = null)
        {
            var stream = new MemoryStream();
            var writer = encoding != null ? new StreamWriter(stream, encoding) : new StreamWriter(stream);
            await writer.WriteAsync(s);
            await writer.FlushAsync();
            stream.Position = 0;
            return stream;
        }
    }
}
