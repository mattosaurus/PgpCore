using FluentAssertions;
using FluentAssertions.Execution;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// Tests for the fluent <see cref="EncryptionKeysBuilder"/>, covering explicit key selection
    /// (#238/#210) and multiple private keys with independent passphrases (#277).
    /// </summary>
    public class EncryptionKeysBuilderTests : TestBase
    {
        [Fact]
        public async Task Build_WithPublicAndPrivateKey_ShouldRoundTrip()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeysBuilder()
                .WithPublicKey(testFactory.PublicKey)
                .WithPrivateKey(testFactory.PrivateKey, testFactory.Password)
                .Build();
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encrypted = await pgp.EncryptAsync(testFactory.Content);
            string decrypted = await pgp.DecryptAsync(encrypted);

            // Assert
            decrypted.Should().Be(testFactory.Content);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task Build_WithMultiplePrivateKeysDifferentPassphrases_ShouldDecryptWithEither()
        {
            // Arrange - two independent key pairs with different passphrases
            TestFactory a = new TestFactory();
            TestFactory b = new TestFactory();
            await a.ArrangeAsync(KeyType.Generated, FileType.Known);
            await b.ArrangeAsync(KeyType.Generated, FileType.Known);

            // Encrypt separately to each recipient's public key
            string encryptedToA = await new PGP(new EncryptionKeys(a.PublicKey)).EncryptAsync(a.Content);
            string encryptedToB = await new PGP(new EncryptionKeys(b.PublicKey)).EncryptAsync(b.Content);

            // A single EncryptionKeys holding BOTH private keys, each with its own passphrase
            EncryptionKeys combinedPrivate = new EncryptionKeysBuilder()
                .WithPrivateKey(a.PrivateKey, a.Password)
                .WithPrivateKey(b.PrivateKey, b.Password)
                .Build();
            PGP pgp = new PGP(combinedPrivate);

            // Act
            string decryptedA = await pgp.DecryptAsync(encryptedToA);
            string decryptedB = await pgp.DecryptAsync(encryptedToB);

            // Assert
            using (new AssertionScope())
            {
                decryptedA.Should().Be(a.Content);
                decryptedB.Should().Be(b.Content);
            }

            // Teardown
            a.Teardown();
            b.Teardown();
        }

        [Fact]
        public async Task Build_WithMultiplePublicKeys_ShouldEncryptToAllRecipients()
        {
            // Arrange
            TestFactory a = new TestFactory();
            TestFactory b = new TestFactory();
            await a.ArrangeAsync(KeyType.Generated, FileType.Known);
            await b.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys multiRecipient = new EncryptionKeysBuilder()
                .WithPublicKey(a.PublicKey)
                .WithPublicKey(b.PublicKey)
                .Build();
            string encrypted = await new PGP(multiRecipient).EncryptAsync(a.Content);

            // Act - each recipient can decrypt independently
            string decryptedByA = await new PGP(new EncryptionKeys(a.PrivateKey, a.Password)).DecryptAsync(encrypted);
            string decryptedByB = await new PGP(new EncryptionKeys(b.PrivateKey, b.Password)).DecryptAsync(encrypted);

            // Assert
            using (new AssertionScope())
            {
                decryptedByA.Should().Be(a.Content);
                decryptedByB.Should().Be(a.Content);
            }

            // Teardown
            a.Teardown();
            b.Teardown();
        }

        [Fact]
        public void Build_WithNoKeys_ShouldThrowInvalidKeyMaterialException()
        {
            // Act
            System.Action act = () => new EncryptionKeysBuilder().Build();

            // Assert
            act.Should().Throw<InvalidKeyMaterialException>();
        }
    }
}
