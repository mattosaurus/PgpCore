using FluentAssertions.Execution;
using FluentAssertions;
using System.Threading.Tasks;
using Xunit;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using System;
using System.Collections.Generic;
using Org.BouncyCastle.Bcpg;

namespace PgpCore.Tests.UnitTests.GenerateKey
{
    public class KeyAsync : TestBase
    {
        [Fact]
        public async Task GenerateKeyAsync_CreatePublicAndPrivateKeys_ShouldCreateKeysWithDefaultProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(
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
                    publicKey.CreationTime.Should().BeCloseTo(DateTime.UtcNow, new TimeSpan(0, 0, 10));
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(1024);
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
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.TripleDes);
                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public async Task GenerateKeyAsync_CreatePublicAndPrivateKeysWithKeyStrength_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(
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
                    publicKey.CreationTime.Should().BeCloseTo(DateTime.UtcNow, new TimeSpan(0, 0, 10));
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
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.TripleDes);
                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public async Task GenerateKeyAsync_CreatePublicAndPrivateKeysWithoutVersion_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(
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
                    publicKey.CreationTime.Should().BeCloseTo(DateTime.UtcNow, new TimeSpan(0, 0, 10));
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(1024);
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
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.TripleDes);
                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public async Task GenerateKeyAsync_CreatePublicAndPrivateKeysWithExpiryDate_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            await pgp.GenerateKeyAsync(
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
                    publicKey.CreationTime.Should().BeCloseTo(DateTime.UtcNow, new TimeSpan(0, 0, 10));
                    publicKey.IsEncryptionKey.Should().BeTrue();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(1024);
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
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(SymmetricKeyAlgorithmTag.TripleDes);
                            }
                        }
                    }
                }
            }
        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }
            throw new ArgumentException("No encryption key found in public key ring.");
        }

        private static IEnumerable<T> GetEnumValues<T>() where T : struct, IConvertible
        {
            foreach (T enumValue in Enum.GetValues(typeof(T)))
            {
                yield return enumValue;
            }
        }

        public static IEnumerable<object[]> GetAllCombinations()
        {
            foreach (CompressionAlgorithmTag compressionAlgorithmTag in GetEnumValues<CompressionAlgorithmTag>())
            foreach (HashAlgorithmTag hashAlgorithmTag in GetEnumValues<HashAlgorithmTag>())
            foreach (SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag in GetEnumValues<SymmetricKeyAlgorithmTag>())
            {
                yield return new object[] { compressionAlgorithmTag, hashAlgorithmTag, symmetricKeyAlgorithmTag };
            }
        }
    }
}
