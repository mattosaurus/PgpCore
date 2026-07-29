using FluentAssertions.Execution;
using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;

namespace PgpCore.Tests.UnitTests.Recipient
{
    public class RecipientsSync : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void GetRecipients_GetTheRecipientOfEncyptedMessage_ShouldReturnRecipientId(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo) { SymmetricKey = testFactory.SymmetricKey };
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            IEnumerable<long> recipients = pgpEncrypt.GetRecipients(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                recipients.Should().NotBeEmpty();
                recipients.Should().HaveCount(1);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    // Encryption targets the ring's encryption key, which for a generated key is the
                    // subkey rather than the master (#285).
                    recipients.Single().Should().BeOneOf(ReadPublicKeyIds(publicKeyStream));
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        public void GetRecipients_GetTheRecipientsOfEncyptedMessage_ShouldReturnRecipientIds(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory1.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(new List<FileInfo>() { testFactory1.PublicKeyFileInfo, testFactory2.PublicKeyFileInfo });
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory1.ContentFileInfo, testFactory1.EncryptedContentFileInfo);
            IEnumerable<long> recipients = pgpEncrypt.GetRecipients(testFactory1.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory1.EncryptedContentFileInfo.Exists.Should().BeTrue();
                recipients.Should().NotBeEmpty();
                recipients.Should().HaveCount(2);

                // One recipient per key ring, each being that ring's encryption key - the subkey for a
                // generated key rather than the master (#285).
                long[] firstRingKeyIds;
                long[] secondRingKeyIds;

                using (Stream publicKeyStream = testFactory1.PublicKeyFileInfo.OpenRead())
                    firstRingKeyIds = ReadPublicKeyIds(publicKeyStream);

                using (Stream publicKeyStream = testFactory2.PublicKeyFileInfo.OpenRead())
                    secondRingKeyIds = ReadPublicKeyIds(publicKeyStream);

                recipients.Should().ContainSingle(id => firstRingKeyIds.Contains(id));
                recipients.Should().ContainSingle(id => secondRingKeyIds.Contains(id));
            }

            // Teardown
            testFactory1.Teardown();
            testFactory2.Teardown();
        }
    }
}
