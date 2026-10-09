using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Models;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Sign
{
    /// <summary>
    /// Sign and EncryptAndSign must honour the configured CompressionAlgorithm rather than always
    /// compressing with Zip, and must emit no compressed packet when compression is disabled.
    /// </summary>
    public class SignCompression : TestBase
    {
        private const string Content = "compression algorithm should be honoured";

        private static async Task<(EncryptionKeys keys, TestFactory testFactory)> ArrangeKeysAsync()
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            return (keys, testFactory);
        }

        private static void AssertCompression(PgpObject firstObject, CompressionAlgorithmTag expected)
        {
            if (expected == CompressionAlgorithmTag.Uncompressed)
            {
                firstObject.Should().NotBeOfType<PgpCompressedData>();
            }
            else
            {
                firstObject.Should().BeOfType<PgpCompressedData>()
                    .Which.Algorithm.Should().Be(expected);
            }
        }

        [Theory]
        [MemberData(nameof(GetCompressionAlgorithmTags))]
        public async Task SignAsync_ShouldUseConfiguredCompressionAlgorithm(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            PGP pgp = new PGP(keys) { CompressionAlgorithm = compressionAlgorithmTag };

            using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(Content));
            using MemoryStream output = new MemoryStream();

            // Act
            await pgp.SignAsync(input, output, armor: false);

            // Assert
            PgpObjectFactory factory = new PgpObjectFactory(output.ToArray());
            AssertCompression(factory.NextPgpObject(), compressionAlgorithmTag);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetCompressionAlgorithmTags))]
        public async Task EncryptAndSignAsync_ShouldUseConfiguredCompressionAlgorithm(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            var (keys, testFactory) = await ArrangeKeysAsync();
            PGP pgp = new PGP(keys) { CompressionAlgorithm = compressionAlgorithmTag };

            using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(Content));
            using MemoryStream output = new MemoryStream();

            // Act
            await pgp.EncryptAndSignAsync(input, output, armor: false);

            // Assert
            PgpObjectFactory factory = new PgpObjectFactory(output.ToArray());
            PgpEncryptedDataList encryptedDataList = factory.NextPgpObject() as PgpEncryptedDataList;
            encryptedDataList.Should().NotBeNull();
            PgpPublicKeyEncryptedData encryptedData = encryptedDataList.GetEncryptedDataObjects()
                .OfType<PgpPublicKeyEncryptedData>()
                .First(d => keys.FindSecretKey(d.KeyId) != null);

            using Stream clear = encryptedData.GetDataStream(keys.FindSecretKey(encryptedData.KeyId));
            AssertCompression(new PgpObjectFactory(clear).NextPgpObject(), compressionAlgorithmTag);

            // Teardown
            testFactory.Teardown();
        }
    }
}
