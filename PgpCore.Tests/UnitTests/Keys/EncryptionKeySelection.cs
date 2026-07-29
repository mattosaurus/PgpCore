using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Xunit;

namespace PgpCore.Tests.UnitTests.Keys
{
    /// <summary>
    /// Regression tests covering which key is chosen for encryption.
    /// A key that declares key flags excluding encryption (e.g. an RSA sign-only key with
    /// key flags 0x03 = certify + sign) must never be used for encryption, even though
    /// BouncyCastle's <see cref="PgpPublicKey.IsEncryptionKey"/> returns true for the RSA-General
    /// algorithm regardless of key flags.
    /// </summary>
    public class EncryptionKeySelection : TestBase
    {
        [Fact]
        public void FindBestEncryptionKey_SignOnlyMasterWithNoEncryptionSubkey_Throws()
        {
            // Arrange - master key flagged certify + sign only, no encryption subkey.
            PgpPublicKeyRing publicKeyRing = GenerateKeyRing(
                masterKeyFlags: PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign,
                addEncryptionSubkey: false);

            // Act
            Action act = () => Utilities.FindBestEncryptionKey(publicKeyRing);

            // Assert - the sign-only key is not a valid encryption choice, so selection fails
            // rather than silently encrypting to the wrong (non-encryption) key.
            act.Should().Throw<NoEncryptionKeyException>();
        }

        [Fact]
        public void FindBestEncryptionKey_SignOnlyMasterWithEncryptionSubkey_SelectsSubkey()
        {
            // Arrange - sign-only master with a dedicated encryption subkey.
            PgpPublicKeyRing publicKeyRing = GenerateKeyRing(
                masterKeyFlags: PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign,
                addEncryptionSubkey: true);

            PgpPublicKey master = publicKeyRing.GetPublicKeys().Cast<PgpPublicKey>().Single(k => k.IsMasterKey);

            // Act
            PgpPublicKey selected = Utilities.FindBestEncryptionKey(publicKeyRing);

            // Assert
            selected.Should().NotBeNull();
            selected.IsMasterKey.Should().BeFalse();
            selected.KeyId.Should().NotBe(master.KeyId);
        }

        [Fact]
        public void FindBestEncryptionKey_MasterWithEncryptionFlags_SelectsMaster()
        {
            // Arrange - single master key carrying encryption flags (matches PgpCore-generated keys).
            PgpPublicKeyRing publicKeyRing = GenerateKeyRing(
                masterKeyFlags: PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign |
                                PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage,
                addEncryptionSubkey: false);

            // Act
            PgpPublicKey selected = Utilities.FindBestEncryptionKey(publicKeyRing);

            // Assert
            selected.Should().NotBeNull();
            selected.IsMasterKey.Should().BeTrue();
        }

        [Fact]
        public void ReadPublicKey_SignOnlyMasterWithNoEncryptionSubkey_Throws()
        {
            // Arrange - serialized public keyring whose only key is sign-only.
            using Stream publicKeyStream = ToStream(GenerateKeyRing(
                masterKeyFlags: PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign,
                addEncryptionSubkey: false));

            // Act
            Action act = () => Utilities.ReadPublicKey(publicKeyStream);

            // Assert
            act.Should().Throw<NoEncryptionKeyException>();
        }

        [Fact]
        public void ReadPublicKey_SignOnlyMasterWithEncryptionSubkey_SelectsSubkey()
        {
            // Arrange
            PgpPublicKeyRing publicKeyRing = GenerateKeyRing(
                masterKeyFlags: PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign,
                addEncryptionSubkey: true);
            PgpPublicKey master = publicKeyRing.GetPublicKeys().Cast<PgpPublicKey>().Single(k => k.IsMasterKey);
            using Stream publicKeyStream = ToStream(publicKeyRing);

            // Act
            PgpPublicKey selected = Utilities.ReadPublicKey(publicKeyStream);

            // Assert
            selected.Should().NotBeNull();
            selected.IsMasterKey.Should().BeFalse();
            selected.KeyId.Should().NotBe(master.KeyId);
        }

        private static Stream ToStream(PgpPublicKeyRing publicKeyRing)
        {
            MemoryStream stream = new MemoryStream();
            publicKeyRing.Encode(stream);
            stream.Position = 0;
            return stream;
        }

        private static PgpPublicKeyRing GenerateKeyRing(int masterKeyFlags, bool addEncryptionSubkey)
        {
            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));

            PgpKeyPair masterKey = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kpg.GenerateKeyPair(), DateTime.UtcNow);

            PgpSignatureSubpacketGenerator masterSubpackets = new PgpSignatureSubpacketGenerator();
            masterSubpackets.SetKeyFlags(false, masterKeyFlags);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification,
                masterKey,
                "test@example.com",
                SymmetricKeyAlgorithmTag.Aes256,
                "password".ToCharArray(),
                true,
                masterSubpackets.Generate(),
                null,
                new SecureRandom());

            if (addEncryptionSubkey)
            {
                PgpKeyPair encryptionSubkey = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kpg.GenerateKeyPair(), DateTime.UtcNow);

                PgpSignatureSubpacketGenerator subkeySubpackets = new PgpSignatureSubpacketGenerator();
                subkeySubpackets.SetKeyFlags(false,
                    PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

                keyRingGen.AddSubKey(encryptionSubkey, subkeySubpackets.Generate(), null);
            }

            return keyRingGen.GeneratePublicKeyRing();
        }

        [Fact]
        public void UseEncryptionKey_WithAKeyIdInTheKeyRing_ShouldSelectThatKey()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            long encryptionKeyId = keys.EncryptKeys.First().KeyId;

            // Act
            keys.UseEncryptionKey(encryptionKeyId);

            // Assert
            keys.PublicKeyRings.Should().OnlyContain(ring =>
                ring.PreferredEncryptionKey != null && ring.PreferredEncryptionKey.KeyId == encryptionKeyId);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void UseEncryptionKey_WithAKeyIdThatIsNotInTheKeyRing_ShouldThrow()
        {
            // Arrange - silently ignoring the request meant encryption continued with the automatically
            // chosen key, so a caller pinning a specific key had no way to know it had not been honoured.
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys keys = new EncryptionKeys(testFactory.PublicKeyFileInfo);

            // Act
            Action act = () => keys.UseEncryptionKey(0x0123456789ABCDEF);

            // Assert
            act.Should().Throw<MissingKeyException>()
                .Which.Message.Should().Contain("123456789ABCDEF");

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void UseEncryptionKey_WithNoPublicKeyMaterial_ShouldThrow()
        {
            // Arrange - a symmetric-only EncryptionKeys has no key rings to search at all.
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Symmetric, FileType.Known);
            EncryptionKeys keys = new EncryptionKeysBuilder()
                .WithSymmetricKey(testFactory.SymmetricKey)
                .Build();

            // Act
            Action act = () => keys.UseEncryptionKey(0x0123456789ABCDEF);

            // Assert
            act.Should().Throw<MissingKeyException>();

            // Teardown
            testFactory.Teardown();
        }
    }
}
