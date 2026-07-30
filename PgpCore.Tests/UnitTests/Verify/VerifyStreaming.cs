using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using PgpCore.Abstractions;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Verify
{
    /// <summary>
    /// Verification against streams that cannot seek, such as network streams (#287). Reading Position on
    /// the input, or rewinding a caller-supplied output stream, throws NotSupportedException on those
    /// streams, so both are only done when the stream reports CanSeek.
    /// </summary>
    public class VerifyStreaming : TestBase
    {
        [Fact]
        public async Task VerifyClearAsync_WithNonSeekableInput_ShouldVerify()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(keys);

            string clearSigned = await pgp.ClearSignAsync("clear signed over a network stream");
            byte[] signedBytes = Encoding.UTF8.GetBytes(clearSigned);

            // Act
            using MemoryStream backing = new MemoryStream(signedBytes);
            using NonSeekableStream input = new NonSeekableStream(backing);
            using MemoryStream output = new MemoryStream();
            bool verified = await pgp.VerifyClearAsync(input, output);

            // Assert
            verified.Should().BeTrue();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task VerifyAsync_WithNonSeekableOutput_ShouldVerify()
        {
            // Arrange - an HTTP response stream is write-only and cannot be rewound.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(keys);

            using MemoryStream contentStream = new MemoryStream(Encoding.UTF8.GetBytes("signed for a response stream"));
            using MemoryStream signed = new MemoryStream();
            await pgp.SignAsync(contentStream, signed, armor: false);
            byte[] signedBytes = signed.ToArray();

            // Act
            using MemoryStream input = new MemoryStream(signedBytes);
            using MemoryStream outputBacking = new MemoryStream();
            using NonSeekableStream output = new NonSeekableStream(outputBacking);
            bool verified = await pgp.VerifyAsync(input, output);

            // Assert
            verified.Should().BeTrue();
            Encoding.UTF8.GetString(outputBacking.ToArray()).Should().Contain("signed for a response stream");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task VerifyClearAsync_WithSeekableInputNotAtStart_ShouldStillReject()
        {
            // Arrange - the position guard must keep rejecting a mid-stream seekable input; only the
            // non-seekable case is exempt.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(keys);

            string clearSigned = await pgp.ClearSignAsync("clear signed");
            byte[] signedBytes = Encoding.UTF8.GetBytes(clearSigned);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(signedBytes);
                input.Position = 1;
                using MemoryStream output = new MemoryStream();
                await pgp.VerifyClearAsync(input, output);
            };

            // Assert
            await act.Should().ThrowAsync<ArgumentException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task IPGP_ShouldExposeGenerateKeyAsync()
        {
            // Arrange - PGP implemented IKeyAsync but IPGP did not compose it, so GenerateKeyAsync was
            // unreachable for anyone depending on the interface (DI or mocking).
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            IPGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo,
                testFactory.UserName, testFactory.Password, strength: 1024, certainty: 12);

            // Assert
            using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                ReadPublicKey(publicKeyStream).Should().NotBeNull();

            // Teardown
            testFactory.Teardown();
        }
    }
}
