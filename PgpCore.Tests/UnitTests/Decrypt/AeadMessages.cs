using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Decrypt
{
    /// <summary>
    /// AEAD session-key packets can be parsed by BouncyCastle without being decryptable.
    /// PgpCore reports their unsupported format before choosing a decryption key.
    /// </summary>
    public class AeadMessages : TestBase
    {
        /// <summary>
        /// A real AEAD/OCB message, produced with GnuPG 2.4.7 via
        /// <c>gpg --force-ocb --symmetric --cipher-algo AES256</c>. Its packet structure is a version 5
        /// symmetric-key encrypted session key packet (tag 3, aead 2) followed by an AEAD encrypted data
        /// packet (tag 20). Held as a literal so the test does not depend on gpg being installed.
        /// </summary>
        private const string OcbEncryptedMessageBase64 =
            "jE0FCQIDCE1nxIYC3ebzYIxKUIki8a0KVNxPmUL4UILWGs7nlxT8NddvZq5fhxEiSMxJYXXf2dulrutJKb9GEnBAFa0gUmcCm7z" +
            "DlgJVtNRZAQkCEFdsS+IqRw8srrPlReX1wdyU6d7nHYNbcx0Oi1y/ClWG4O/m8a7xK5YWflIB/Tx0q6YOZp6YuY+zVZ5aRemvmb" +
            "/aMyj8BGMAxddcrsuUnkw2rtq5K14=";

        private static byte[] OcbEncryptedMessage => Convert.FromBase64String(OcbEncryptedMessageBase64);

        // GnuPG 2.4.4 --force-ocb --encrypt using Constants.PUBLICKEY1: a version 3
        // public-key session packet followed by tag 20, as produced by Kleopatra.
        private const string PublicKeyOcbMessage =
            "hIwDHCBL6iCIoI8BA/9Kc/oyjM3SWmRB9TzGwc0K4pW4VSU5mIT1C6sdIP75+B2n1kZNC1VWEp4f1L34sjKZnIQv3vvA++ie2QUwnKM5wMXB9G3WazeW4WmevpqV1FF2KG4xKHvWZTLhASDudyePBWevKI7FslOxhRidlVUli/r6DB+UKSCdEXt9n2pR1dRjAQkCEKjWmVrf5NwLP1sVMTmyoD8/dB5YgaZfe0AnPPRkqWvYxt2smfuNgwlgD+EYUX0dsyYyGj+byibIsjJHKIO0HwXDiqMlWRfevEuT8LAPaptvyZK8lsKg5LGbApgeCbpv";

        [Theory]
        [InlineData("decrypt", false, false)]
        [InlineData("decrypt", true, false)]
        [InlineData("decrypt", false, true)]
        [InlineData("decrypt", true, true)]
        [InlineData("decryptVerify", false, false)]
        [InlineData("decryptVerify", true, true)]
        [InlineData("inspect", false, false)]
        [InlineData("inspect", true, true)]
        public async Task PublicKeyOcb_ReportsUnsupportedEncryptionBeforeReadingPayload(string operation, bool armored, bool nonSeekable)
        {
            byte[] message = Convert.FromBase64String(PublicKeyOcbMessage);
            if (armored)
            {
                using var encoded = new MemoryStream();
                using (var armor = new ArmoredOutputStream(encoded)) armor.Write(message);
                message = encoded.ToArray();
            }
            using var bytes = new MemoryStream(message);
            using Stream input = nonSeekable ? new NonSeekableStream(bytes) : bytes;
            using var output = new MemoryStream();
            var pgp = new PGP(new EncryptionKeys(Constants.PRIVATEKEY1, Constants.PASSWORD1));
            UnsupportedAeadException error = await Assert.ThrowsAsync<UnsupportedAeadException>(async () =>
            {
                if (operation == "inspect") await pgp.InspectAsync(input);
                else if (operation == "decryptVerify") await pgp.DecryptAndVerifyAsync(input, output);
                else await pgp.DecryptAsync(input, output);
            });
            Assert.Contains("AEAD", error.Message);
            Assert.Equal(0, output.Length);
        }

        /// <summary>
        /// A packet whose tag is unknown to BouncyCastle but is not the AEAD tag. 0xD5 is a new-format
        /// header for tag 21 (the padding packet), which BouncyCastle also has no entry for, so it produces
        /// the same class of error with a different tag number.
        /// </summary>
        private static byte[] UnknownNonAeadPacket => new byte[] { 0xD5, 0x03, 0x01, 0x02, 0x03 };

        private static PGP ArrangePgp(TestFactory testFactory) =>
            new PGP(new EncryptionKeys(testFactory.PrivateKey, testFactory.Password));

        [Fact]
        public async Task DecryptAsync_AeadEncryptedMessage_ShouldThrowUnsupportedAeadException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = ArrangePgp(testFactory);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(OcbEncryptedMessage);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAsync(input, output);
            };

            // Assert
            (await act.Should().ThrowAsync<UnsupportedAeadException>())
                .Which.Message.Should().Contain("AEAD").And.Contain("219");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_AeadEncryptedMessage_ShouldReportTheUnsupportedSessionKeyVersion()
        {
            // The error identifies the structurally recognized but unsupported packet version.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = ArrangePgp(testFactory);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(OcbEncryptedMessage);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAsync(input, output);
            };

            // Assert
            UnsupportedAeadException exception = (await act.Should().ThrowAsync<UnsupportedAeadException>()).Which;
            exception.Message.Should().Contain("session-key packet version 5");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_AeadEncryptedMessage_ShouldThrowUnsupportedAeadException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = new PGP(new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password));

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(OcbEncryptedMessage);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAndVerifyAsync(input, output);
            };

            // Assert
            await act.Should().ThrowAsync<UnsupportedAeadException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task InspectAsync_AeadEncryptedMessage_ShouldThrowUnsupportedAeadException()
        {
            // Arrange - Inspect previously surfaced BouncyCastle's raw IOException unwrapped.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = ArrangePgp(testFactory);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(OcbEncryptedMessage);
                await pgp.InspectAsync(input);
            };

            // Assert
            await act.Should().ThrowAsync<UnsupportedAeadException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_UnknownPacketThatIsNotAead_ShouldNotBeReportedAsAead()
        {
            // Arrange - a different unrecognised packet tag must keep the generic error. If the AEAD match
            // were widened to any "unknown packet type" message, this would wrongly report AEAD.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = ArrangePgp(testFactory);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(UnknownNonAeadPacket);
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAsync(input, output);
            };

            // Assert
            await act.Should().ThrowAsync<NotEncryptedDataException>();
            await act.Should().NotThrowAsync<UnsupportedAeadException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAsync_PlainText_ShouldNotBeReportedAsAead()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = ArrangePgp(testFactory);

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes("this is not PGP data at all"));
                using MemoryStream output = new MemoryStream();
                await pgp.DecryptAsync(input, output);
            };

            // Assert
            await act.Should().ThrowAsync<NotEncryptedDataException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void UnsupportedAeadException_ShouldCarryMessageAndInnerException()
        {
            // Arrange
            IOException inner = new IOException("unknown packet type encountered: 20");

            // Act
            UnsupportedAeadException withMessage = new UnsupportedAeadException("message only");
            UnsupportedAeadException withInner = new UnsupportedAeadException("wrapped", inner);

            // Assert
            withMessage.Message.Should().Be("message only");
            withMessage.Should().BeAssignableTo<PgpCoreException>();
            withInner.Message.Should().Be("wrapped");
            withInner.InnerException.Should().BeSameAs(inner);
        }
    }
}
