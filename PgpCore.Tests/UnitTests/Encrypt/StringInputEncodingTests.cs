using FluentAssertions;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    public class StringInputEncodingTests
    {
        [Fact]
        public async Task EncryptAsync_StrictUtf8_RejectsUnpairedSurrogates()
        {
            var keys = new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1);
            var pgp = new PGP(keys) { TextEncoding = new UTF8Encoding(false, true) };
            System.Func<Task> encrypt = () => pgp.EncryptAsync("\uD800");
            await encrypt.Should().ThrowAsync<EncoderFallbackException>();
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public async Task EncryptAsync_StringInput_PreservesEncodedPayloadBytes(bool emitPreamble, bool empty)
        {
            // Byte-level proof catches conversion errors that a matching string decoder could hide.
            var encoding = new UTF8Encoding(emitPreamble);
            string content = empty ? string.Empty : new string('\u00E9', 32768) + "\uD83D\uDE00\uD800";
            var keys = new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1);
            var pgp = new PGP(keys) { TextEncoding = encoding };

            string encrypted = await pgp.EncryptAsync(content);
            using var input = new MemoryStream(Encoding.ASCII.GetBytes(encrypted));
            using var output = new MemoryStream();
            await pgp.DecryptAsync(input, output);

            output.ToArray().Should().Equal(encoding.GetPreamble().Concat(encoding.GetBytes(content)));
        }
    }
}
