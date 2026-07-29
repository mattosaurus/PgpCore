using FluentAssertions.Execution;
using FluentAssertions;
using Xunit;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Bcpg;

namespace PgpCore.Tests.UnitTests.Keys
{
    public class GenerateKeySync : TestBase
    {
        [Fact]
        public void GenerateKey_CreatePublicAndPrivateKeys_ShouldCreateKeysWithDefaultProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = publicKey = ReadPublicKey(publicKeyStream);
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    ShouldHavePlausibleCreationTime(publicKey);
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(3072);
                }

            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        // A generated key is a certify/sign master key plus an encryption subkey (#285).
                        PgpSecretKey[] secretKeys = kRing.GetSecretKeys().Cast<PgpSecretKey>().ToArray();
                        secretKeys.Should().HaveCount(2);

                        PgpSecretKey masterKey = secretKeys.Single(k => k.IsMasterKey);
                        masterKey.IsSigningKey.Should().BeTrue();
                        masterKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);

                        PgpSecretKey encryptionSubKey = secretKeys.Single(k => !k.IsMasterKey);
                        encryptionSubKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);
                    }
                }
            }
        }

        [Fact]
        public void GenerateKey_CreatePublicAndPrivateKeysWithKeyStrength_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password,
                strength: 2048
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = publicKey = ReadPublicKey(publicKeyStream);
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    ShouldHavePlausibleCreationTime(publicKey);
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(2048);
                }
            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        // A generated key is a certify/sign master key plus an encryption subkey (#285).
                        PgpSecretKey[] secretKeys = kRing.GetSecretKeys().Cast<PgpSecretKey>().ToArray();
                        secretKeys.Should().HaveCount(2);

                        PgpSecretKey masterKey = secretKeys.Single(k => k.IsMasterKey);
                        masterKey.IsSigningKey.Should().BeTrue();
                        masterKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);

                        PgpSecretKey encryptionSubKey = secretKeys.Single(k => !k.IsMasterKey);
                        encryptionSubKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);
                    }
                }
            }
        }

        [Fact]
        public void GenerateKey_CreatePublicAndPrivateKeysWithoutVersion_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password,
                emitVersion: false
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().NotContain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    ShouldHavePlausibleCreationTime(publicKey);
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(3072);
                }

            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().NotContain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        // A generated key is a certify/sign master key plus an encryption subkey (#285).
                        PgpSecretKey[] secretKeys = kRing.GetSecretKeys().Cast<PgpSecretKey>().ToArray();
                        secretKeys.Should().HaveCount(2);

                        PgpSecretKey masterKey = secretKeys.Single(k => k.IsMasterKey);
                        masterKey.IsSigningKey.Should().BeTrue();
                        masterKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);

                        PgpSecretKey encryptionSubKey = secretKeys.Single(k => !k.IsMasterKey);
                        encryptionSubKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);
                    }
                }
            }
        }

        [Fact]
        public void GenerateKey_CreatePublicAndPrivateKeysWithExpiryDate_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password,
                keyExpirationInSeconds: 60
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    ShouldHavePlausibleCreationTime(publicKey);
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(3072);
                    publicKey.GetValidSeconds().Should().Be(60);
                }

            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        // A generated key is a certify/sign master key plus an encryption subkey (#285).
                        PgpSecretKey[] secretKeys = kRing.GetSecretKeys().Cast<PgpSecretKey>().ToArray();
                        secretKeys.Should().HaveCount(2);

                        PgpSecretKey masterKey = secretKeys.Single(k => k.IsMasterKey);
                        masterKey.IsSigningKey.Should().BeTrue();
                        masterKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);

                        PgpSecretKey encryptionSubKey = secretKeys.Single(k => !k.IsMasterKey);
                        encryptionSubKey.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.Aes256);
                    }
                }
            }
        }

        [Fact]
        public void GenerateKey_WithEdDsaAlgorithm_ShouldSignAndVerifyRoundTrip()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.EdDsa };

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password
                );

            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            string signedContent = pgpSign.Sign(testFactory.Content);
            bool verified = pgpVerify.Verify(signedContent);

            // Assert
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKeyRingBundle bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
                    PgpPublicKey masterKey = GetMasterKey(bundle);
                    masterKey.Should().NotBeNull();
                    masterKey.Algorithm.Should().Be(PublicKeyAlgorithmTag.EdDsa);
                }

                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void GenerateKey_WithECDsaAlgorithm_ShouldSignAndVerifyRoundTrip()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.ECDsa };

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password
                );

            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            string signedContent = pgpSign.Sign(testFactory.Content);
            bool verified = pgpVerify.Verify(signedContent);

            // Assert
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKeyRingBundle bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
                    PgpPublicKey masterKey = GetMasterKey(bundle);
                    masterKey.Should().NotBeNull();
                    masterKey.Algorithm.Should().Be(PublicKeyAlgorithmTag.ECDsa);
                }

                verified.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void GenerateKey_WithUnsupportedAlgorithm_ShouldThrowNotSupportedException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.DiffieHellman };

            // Act
            Action act = () => pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password
                );

            // Assert
            act.Should().Throw<NotSupportedException>();

            // Teardown
            testFactory.Teardown();
        }

        private static PgpPublicKey GetMasterKey(PgpPublicKeyRingBundle bundle)
        {
            foreach (PgpPublicKeyRing keyRing in bundle.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsMasterKey)
                        return key;
                }
            }
            return null;
        }
    }
}
