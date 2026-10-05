using FluentAssertions;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    public class ArmoredStringEncodingTests
    {
        private const string Content = "caf\u00E9 na\u00EFve r\u00E9sum\u00E9";

        private static PGP CreatePgp(string encoding)
        {
            var keys = new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1);
            return new PGP(keys)
            {
                TextEncoding = encoding switch
                {
                    "utf8-bom" => new UTF8Encoding(true),
                    "utf16" => Encoding.Unicode,
                    "utf32" => Encoding.UTF32,
                    "latin1" => Encoding.Latin1,
                    _ => new UTF8Encoding(false)
                }
            };
        }

        [Theory]
        [InlineData("utf8-bom")]
        [InlineData("utf16")]
        [InlineData("utf32")]
        [InlineData("latin1")]
        public async Task EncryptAndDecrypt_ArmoredStrings_PreserveTextEncoding(string encoding)
        {
            var pgp = CreatePgp(encoding);
            string encrypted = await pgp.EncryptAsync(Content);
            encrypted.Should().StartWith("-----BEGIN PGP MESSAGE-----");
            (await pgp.DecryptAsync(encrypted)).Should().Be(Content);
            var inspection = await pgp.InspectAsync(encrypted);
            inspection.IsArmored.Should().BeTrue();
            inspection.IsEncrypted.Should().BeTrue();
            pgp.GetRecipients(encrypted).Should().NotBeEmpty();
            pgp.GetArmoredStringRecipients(encrypted).Should().Equal(pgp.GetRecipients(encrypted));

            string signed = await pgp.EncryptAndSignAsync(Content);
            (await pgp.DecryptAndVerifyAsync(signed)).Should().Be(Content);
        }

        [Theory]
        [InlineData("utf8-bom")]
        [InlineData("utf16")]
        [InlineData("utf32")]
        [InlineData("latin1")]
        public async Task SignAndVerify_ArmoredStrings_PreserveTextEncoding(string encoding)
        {
            var pgp = CreatePgp(encoding);
            string signed = await pgp.SignAsync(Content);
            signed.Should().StartWith("-----BEGIN PGP MESSAGE-----");
            (await pgp.VerifyAsync(signed)).Should().BeTrue();
            var result = await pgp.VerifyAndReadSignedArmoredStringAsync(signed);
            result.IsVerified.Should().BeTrue();
            result.ClearText.Should().Be(Content);
        }

        [Theory]
        [InlineData("utf8-bom")]
        [InlineData("utf16")]
        [InlineData("utf32")]
        [InlineData("latin1")]
        public async Task DetachedSignature_ArmoredStrings_PreserveTextEncoding(string encoding)
        {
            var pgp = CreatePgp(encoding);
            string signature = await pgp.SignDetachedAsync(Content);
            signature.Should().StartWith("-----BEGIN PGP SIGNATURE-----");
            (await pgp.VerifyDetachedAsync(Content, signature)).Should().BeTrue();
        }

        [Theory]
        [InlineData("utf8-bom")]
        [InlineData("utf16")]
        [InlineData("utf32")]
        [InlineData("latin1")]
        public async Task ClearSignedStrings_PreserveUnicodeIndependentlyOfPayloadEncoding(string encoding)
        {
            const string content = "caf\u00E9 \u65E5\u672C \uD83D\uDE00";
            var pgp = CreatePgp(encoding);
            string signed = await pgp.ClearSignAsync(content);
            signed.Should().StartWith("-----BEGIN PGP SIGNED MESSAGE-----");
            (await pgp.VerifyClearAsync(signed)).Should().BeTrue();
            var result = await pgp.VerifyAndReadClearArmoredStringAsync(signed);
            result.IsVerified.Should().BeTrue();
            result.ClearText.TrimEnd('\r', '\n').Should().Be(content);
            var generalResult = await pgp.VerifyAndReadSignedArmoredStringAsync(signed);
            generalResult.IsVerified.Should().BeTrue();
            generalResult.ClearText.TrimEnd('\r', '\n').Should().Be(content);
        }

        [Fact]
        public async Task GeneralSignedStreamReader_ReadsVerifiedCleartextFromStart()
        {
            var pgp = CreatePgp("utf8");
            string signed = await pgp.ClearSignAsync(Content);
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(signed));

            var result = await pgp.VerifyAndReadSignedStreamAsync(input);

            result.IsVerified.Should().BeTrue();
            result.ClearText.TrimEnd('\r', '\n').Should().Be(Content);
        }
    }
}
