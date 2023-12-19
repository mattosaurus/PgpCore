using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests
{
    public class DecryptAsync
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptAsync_DecryptEncryptedMessage_MessageShouldDecrypt(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
