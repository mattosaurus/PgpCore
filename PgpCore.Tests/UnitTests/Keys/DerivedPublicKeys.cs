using FluentAssertions;
using FluentAssertions.Execution;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// A secret key ring carries its own public key material, so an <see cref="EncryptionKeys"/> built from
    /// only a private key derives its public keys rather than leaving them null. Previously every public key
    /// property was null in that case, and encrypting threw a bare
    /// <see cref="NullReferenceException"/> (GitHub issue #316).
    /// </summary>
    public class DerivedPublicKeys : TestBase
    {
        [Fact]
        public async Task PrivateKeyOnly_ShouldDerivePublicKeys()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            // Act
            EncryptionKeys keys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            // Assert
            using (new AssertionScope())
            {
                keys.PublicKeyRings.Should().NotBeNullOrEmpty();
                keys.EncryptKeys.Should().NotBeNullOrEmpty();
                keys.VerificationKeys.Should().NotBeNullOrEmpty();
                keys.MasterKey.Should().NotBeNull();
                // The derived keys must belong to the supplied private key.
                keys.MasterKey.KeyId.Should().Be(keys.SigningSecretKey.PublicKey.KeyId);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task PrivateKeyOnly_ShouldEncryptAndDecrypt()
        {
            // Arrange - this is the call that previously threw NullReferenceException.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = new PGP(new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password));

            // Act
            string encrypted = await pgp.EncryptAsync("derived key round trip");
            string decrypted = await pgp.DecryptAsync(encrypted);

            // Assert
            decrypted.Trim().Should().Be("derived key round trip");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task PrivateKeyOnly_ShouldEncryptAndSignThenDecryptAndVerify()
        {
            // Arrange - verification also needs the derived public keys.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            PGP pgp = new PGP(new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password));

            // Act
            string encrypted = await pgp.EncryptAndSignAsync("derived key signed round trip");
            string decrypted = await pgp.DecryptAndVerifyAsync(encrypted);

            // Assert
            decrypted.Trim().Should().Be("derived key signed round trip");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task SymmetricKeyOnly_ShouldHaveNoPublicKeysButStillEncrypt()
        {
            // Arrange - with neither public nor private key material there is nothing to derive from.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Symmetric, FileType.Known);

            EncryptionKeys keys = new EncryptionKeysBuilder()
                .WithSymmetricKey(testFactory.SymmetricKey)
                .Build();

            // Act
            PGP pgp = new PGP(keys);
            string encrypted = await pgp.EncryptAsync("symmetric only");
            string decrypted = await pgp.DecryptAsync(encrypted);

            // Assert
            using (new AssertionScope())
            {
                keys.PublicKeyRings.Should().BeNull();
                keys.EncryptKeys.Should().BeNull();
                keys.MasterKey.Should().BeNull();
                decrypted.Trim().Should().Be("symmetric only");
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task Encrypt_WithNoEncryptionKeyAndNoSymmetricKey_ShouldThrowNoEncryptionKeyException()
        {
            // Arrange - SymmetricKey is publicly settable, so it can be cleared after construction leaving
            // nothing to encrypt to. That used to reach BouncyCastle as "no encryption methods specified".
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Symmetric, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.SymmetricKey);
            keys.SymmetricKey = null;
            PGP pgp = new PGP(keys);

            // Act
            Func<Task> act = async () => await pgp.EncryptAsync("no recipients");

            // Assert
            await act.Should().ThrowAsync<NoEncryptionKeyException>();

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public async Task EncryptAndSign_WithNoEncryptionKeyAndNoSymmetricKey_ShouldThrowNoEncryptionKeyException()
        {
            // Arrange - the sign path builds its recipients through a different code path to Encrypt.
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);

            EncryptionKeys keys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            keys.UseEncryptionKey(keys.EncryptKeys.First().KeyId);
            PGP pgp = new PGP(keys);

            // Sanity: with a derived encryption key this succeeds.
            string encrypted = await pgp.EncryptAndSignAsync("has a recipient");
            encrypted.Should().NotBeNullOrEmpty();

            // Act - now remove every recipient.
            EncryptionKeys symmetricOnly = new EncryptionKeys(testFactory.SymmetricKey ?? new byte[] { 1, 2, 3, 4 });
            symmetricOnly.SymmetricKey = null;
            PGP pgpWithoutRecipients = new PGP(symmetricOnly);
            Func<Task> act = async () => await pgpWithoutRecipients.EncryptAsync("no recipients");

            // Assert
            await act.Should().ThrowAsync<NoEncryptionKeyException>();

            // Teardown
            testFactory.Teardown();
        }
    }
}
