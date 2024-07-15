﻿using FluentAssertions.Execution;
using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using PgpCore.Models;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    public class EncryptAsync_File : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageWithDefaultProperties_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactory.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptEmptyMessageWithDefaultProperties_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            // Create empty file
            testFactory.ContentFileInfo.Create().Close();
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactory.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageAsBinary_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeFalse();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().NotBeNullOrEmpty();
                pgpInspectResult.MessageHeaders.Should().BeNullOrEmpty();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageWithoutIntegrityCheck_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeFalse();
                pgpInspectResult.FileName.Should().Be(testFactory.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageWithName_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, name: TESTNAME);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(TESTNAME);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageWithHeaders_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, headers: new Dictionary<string, string> { { TESTHEADERKEY, TESTHEADERVALUE } });

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactory.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(2);
                pgpInspectResult.MessageHeaders.First().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.First().Value.Should().Be(VERSION);
                pgpInspectResult.MessageHeaders.Last().Key.Should().Be(TESTHEADERKEY);
                pgpInspectResult.MessageHeaders.Last().Value.Should().Be(TESTHEADERVALUE);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageAndOverwriteVersionHeader_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, headers: new Dictionary<string, string> { { "Version", TESTHEADERVALUE } });

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactory.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(TESTHEADERVALUE);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageWithOldFormat_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            await pgpEncrypt.EncryptAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactory.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithDefaultProperties_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpInspect = new PGP(inspectionKeys);

            // Act
            await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.ContentFileInfo, testFactoryEncrypt.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactoryEncrypt.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAndSignAsync_EncryptAndSignMessageAsBinary_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpInspect = new PGP(inspectionKeys);

            // Act
            await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.ContentFileInfo, testFactoryEncrypt.EncryptedContentFileInfo, armor: false);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeFalse();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().NotBeNullOrEmpty();
                pgpInspectResult.MessageHeaders.Should().BeNullOrEmpty();
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithoutIntegrityCheck_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpInspect = new PGP(inspectionKeys);

            // Act
            await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.ContentFileInfo, testFactoryEncrypt.EncryptedContentFileInfo, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeFalse();
                pgpInspectResult.FileName.Should().Be(testFactoryEncrypt.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithName_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpInspect = new PGP(inspectionKeys);

            // Act
            await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.ContentFileInfo, testFactoryEncrypt.EncryptedContentFileInfo, name: TESTNAME);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(TESTNAME);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithHeaders_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpInspect = new PGP(inspectionKeys);

            // Act
            await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.ContentFileInfo, testFactoryEncrypt.EncryptedContentFileInfo, headers: new Dictionary<string, string> { { TESTHEADERKEY, TESTHEADERVALUE } });

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactoryEncrypt.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(2);
                pgpInspectResult.MessageHeaders.First().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.First().Value.Should().Be(VERSION);
                pgpInspectResult.MessageHeaders.Last().Key.Should().Be(TESTHEADERKEY);
                pgpInspectResult.MessageHeaders.Last().Value.Should().Be(TESTHEADERVALUE);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithOldFormat_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpInspect = new PGP(inspectionKeys);

            // Act
            await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.ContentFileInfo, testFactoryEncrypt.EncryptedContentFileInfo, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(testFactoryEncrypt.ContentFileInfo.Name);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }
    }
}
