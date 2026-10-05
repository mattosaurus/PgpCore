using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Extensions
{
    internal static class StringExtensions
    {
        // Match StreamWriter's default encoding, including invalid-surrogate rejection.
        private static readonly Encoding DefaultEncoding = new UTF8Encoding(false, true);

        public static Stream GetStream(this string s, Encoding encoding = null)
        {
            s = s ?? string.Empty;
            encoding = encoding ?? DefaultEncoding;
            byte[] preamble = encoding.GetPreamble();
            byte[] bytes = new byte[checked(preamble.Length + encoding.GetByteCount(s))];
            preamble.CopyTo(bytes, 0);
            encoding.GetBytes(s, 0, s.Length, bytes, preamble.Length);
            return new MemoryStream(bytes);
        }

        public static Task<Stream> GetStreamAsync(this string s, Encoding encoding = null)
            => Task.FromResult(GetStream(s, encoding));
    }
}
