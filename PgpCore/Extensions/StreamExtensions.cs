using System.IO;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Extensions
{
    internal static class StreamExtensions
    {
        public static string GetString(this Stream inputStream)
        {
            var reader = new StreamReader(inputStream);
            var output = reader.ReadToEnd();
            return output;
        }

        public static async Task<string> GetStringAsync(this Stream inputStream)
        {
            var reader = new StreamReader(inputStream);
            var output = await reader.ReadToEndAsync();
            return output;
        }

        public static Encoding GetEncoding(this Stream inputStream)
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
