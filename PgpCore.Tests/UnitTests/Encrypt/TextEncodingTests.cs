using FluentAssertions;
using FluentAssertions.Execution;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    /// <summary>
    /// The string based overloads convert between strings and bytes using <see cref="PGP.TextEncoding"/>,
    /// defaulting to UTF-8 without a byte order mark (the historical behaviour). Setting it allows
    /// interop with counterparties that produce or expect a specific legacy encoding, instead of
    /// hardcoding one (GitHub PR #307 wanted Windows-1253 baked in).
    /// </summary>
    public class TextEncodingTests : TestBase
    {
        private const string AccentedContent = "café naïve résumé";

        private static async Task<(PGP pgp, TestFactory testFactory)> ArrangePgpAsync()
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            return (new PGP(keys), testFactory);
        }

        [Fact]
        public void TextEncoding_ShouldDefaultToUtf8WithoutByteOrderMark()
        {
            // Arrange / Act
            PGP pgp = new PGP();

            // Assert - a BOM-emitting default would prepend three bytes to every string overload's
            // plaintext, changing what round trips against older versions and other tools.
            using (new AssertionScope())
            {
                pgp.TextEncoding.Should().BeOfType<UTF8Encoding>();
                pgp.TextEncoding.GetPreamble().Should().BeEmpty();
            }
        }

        [Fact]
        public async Task EncryptAsync_WithLatin1TextEncoding_ShouldRoundTripThroughStringOverloads()
        {
            // Arrange
            var (pgp, testFactory) = await ArrangePgpAsync();
            pgp.TextEncoding = Encoding.Latin1;

            // Act
            string encrypted = await pgp.EncryptAsync(AccentedContent);
            string decrypted = await pgp.DecryptAsync(encrypted);

            // Assert
            decrypted.Should().Be(AccentedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task EncryptAsync_WithLatin1TextEncoding_ShouldProduceLatin1Bytes()
        {
            // Arrange - the encoding must change the actual plaintext bytes, not just survive a round
            // trip (UTF-8 both sides would round trip too).
            var (pgp, testFactory) = await ArrangePgpAsync();
            pgp.TextEncoding = Encoding.Latin1;

            // Act - encrypt via the string overload, decrypt via the stream overload so the raw
            // literal data bytes are observable.
            string encrypted = await pgp.EncryptAsync(AccentedContent);
            using MemoryStream input = new MemoryStream(Encoding.ASCII.GetBytes(encrypted));
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAsync(input, output);

            // Assert - 'é' is a single 0xE9 byte in Latin-1, two bytes (0xC3 0xA9) in UTF-8.
            output.ToArray().Should().Equal(Encoding.Latin1.GetBytes(AccentedContent));

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_WithMismatchedTextEncoding_ShouldNotRoundTrip()
        {
            // Arrange - documents why the setting matters: the encoding must match on both sides.
            var (pgp, testFactory) = await ArrangePgpAsync();
            pgp.TextEncoding = Encoding.Latin1;
            string encrypted = await pgp.EncryptAsync(AccentedContent);

            // Act - decrypt with the default UTF-8 instead.
            pgp.TextEncoding = new UTF8Encoding(false);
            string decrypted = await pgp.DecryptAsync(encrypted);

            // Assert - Latin-1 bytes are not valid UTF-8 for the accented characters.
            decrypted.Should().NotBe(AccentedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task SignAsync_WithLatin1TextEncoding_ShouldVerifyAndReadOriginalContent()
        {
            // Arrange - the sign/verify string overloads share the same conversions.
            var (pgp, testFactory) = await ArrangePgpAsync();
            pgp.TextEncoding = Encoding.Latin1;

            // Act
            string signed = await pgp.SignAsync(AccentedContent);
            Models.VerificationResult result = await pgp.VerifyAndReadSignedArmoredStringAsync(signed);

            // Assert
            using (new AssertionScope())
            {
                result.IsVerified.Should().BeTrue();
                result.ClearText.Should().Be(AccentedContent);
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
