using FluentAssertions;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Verify
{
    /// <summary>
    /// A signature inside an encrypted message cannot be verified without decrypting, so Verify always
    /// throws for encrypted input. Previously, with <c>throwIfEncrypted</c> left at its default of false,
    /// it returned true when the message was merely encrypted *to* a known key id - a result any sender
    /// can produce, unrelated to any signature, and easily mistaken for successful verification.
    /// </summary>
    public class VerifyEncryptedInput : TestBase
    {
        private static async Task<(byte[] encrypted, PGP pgp, TestFactory testFactory)> ArrangeEncryptedMessageAsync()
        {
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(keys);

            using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(testFactory.Content));
            using MemoryStream encrypted = new MemoryStream();
            await pgp.EncryptAndSignAsync(input, encrypted, armor: false);

            return (encrypted.ToArray(), pgp, testFactory);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task VerifyAsync_EncryptedInput_ShouldThrowRegardlessOfThrowIfEncrypted(bool throwIfEncrypted)
        {
            // Arrange - the message is signed AND encrypted to the verifier's own key, so under the old
            // key-id presence check the throwIfEncrypted=false case reported verified=true.
            var (encrypted, pgp, testFactory) = await ArrangeEncryptedMessageAsync();

            // Act
            Func<Task> act = async () =>
            {
                using MemoryStream input = new MemoryStream(encrypted);
                await pgp.VerifyAsync(input, null, throwIfEncrypted);
            };

            // Assert
            (await act.Should().ThrowAsync<ArgumentException>())
                .Which.Message.Should().Contain("DecryptAndVerify");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task DecryptAndVerifyAsync_SameEncryptedInput_ShouldRemainTheWorkingPath()
        {
            // Arrange - the exception points callers at DecryptAndVerify, so that route must work.
            var (encrypted, pgp, testFactory) = await ArrangeEncryptedMessageAsync();

            // Act
            using MemoryStream input = new MemoryStream(encrypted);
            using MemoryStream output = new MemoryStream();
            await pgp.DecryptAndVerifyAsync(input, output);

            // Assert
            Encoding.UTF8.GetString(output.ToArray()).Should().Be(testFactory.Content);

            // Teardown
            testFactory.Teardown();
        }
    }
}
