using System.IO;
using System.Text;

namespace PgpCore
{
	public static class StreamHelper
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

		public static string GetString(this Stream inputStream)
		{
			var reader = new StreamReader(inputStream);
			var       output = reader.ReadToEnd();
			return output;
		}
	}
}