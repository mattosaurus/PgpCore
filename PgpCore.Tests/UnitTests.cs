using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace PgpCore.Tests
{
    public class UnitTests
    {
        [Fact]
        public void GenerateKey_CreatePublicPrivateKeyFiles()
        {
            // Arrange
            Directory.CreateDirectory(keyDirectory);
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(publicKeyFilePath1, privateKeyFilePath1, password1);

            // Assert
            Assert.True(File.Exists(publicKeyFilePath1));
            Assert.True(File.Exists(privateKeyFilePath1));
        }

        #region File
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptFile_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFile(contentFilePath, encryptedContentFilePath, publicKeyFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void SignFile_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.SignFile(contentFilePath, signedContentFilePath, privateKeyFilePath1, password1);

            // Assert
            Assert.True(File.Exists(signedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptFile_CreateEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                publicKeyFilePath1,
                publicKeyFilePath2
            };

            // Act
            pgp.EncryptFile(contentFilePath, encryptedContentFilePath, keys);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptFileAndSign_CreateEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(contentFilePath, encryptedContentFilePath, publicKeyFilePath1, privateKeyFilePath1, password1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptFileAndSign_CreateEncryptedAndSignedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                publicKeyFilePath1,
                publicKeyFilePath2
            };

            // Act
            pgp.EncryptFileAndSign(contentFilePath, encryptedContentFilePath, keys, privateKeyFilePath1, password1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptFile_DecryptEncryptedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFile(contentFilePath, encryptedContentFilePath, publicKeyFilePath1);
            pgp.DecryptFile(encryptedContentFilePath, decryptedContentFilePath1, privateKeyFilePath1, password1);
            string decryptedContent = File.ReadAllText(decryptedContentFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.Equal(content, decryptedContent.Trim());

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptFile_DecryptEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                publicKeyFilePath1,
                publicKeyFilePath2
            };

            // Act
            pgp.EncryptFile(contentFilePath, encryptedContentFilePath, keys);
            pgp.DecryptFile(encryptedContentFilePath, decryptedContentFilePath1, privateKeyFilePath1, password1);
            pgp.DecryptFile(encryptedContentFilePath, decryptedContentFilePath2, privateKeyFilePath2, password2);
            string decryptedContent1 = File.ReadAllText(decryptedContentFilePath1);
            string decryptedContent2 = File.ReadAllText(decryptedContentFilePath2);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.True(File.Exists(decryptedContentFilePath2));
            Assert.Equal(content, decryptedContent1.Trim());
            Assert.Equal(content, decryptedContent2.Trim());

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptFile_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(contentFilePath, encryptedContentFilePath, publicKeyFilePath1, privateKeyFilePath1, password1);
            pgp.DecryptFile(encryptedContentFilePath, decryptedContentFilePath1, privateKeyFilePath1, password1);
            string decryptedContent = File.ReadAllText(decryptedContentFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.Equal(content, decryptedContent.Trim());

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptFile_DecryptSignedAndEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();
            List<string> keys = new List<string>()
            {
                publicKeyFilePath1,
                publicKeyFilePath2
            };

            // Act
            pgp.EncryptFileAndSign(contentFilePath, encryptedContentFilePath, keys, privateKeyFilePath1, password1);
            pgp.DecryptFile(encryptedContentFilePath, decryptedContentFilePath1, privateKeyFilePath1, password1);
            pgp.DecryptFile(encryptedContentFilePath, decryptedContentFilePath2, privateKeyFilePath2, password2);
            string decryptedContent1 = File.ReadAllText(decryptedContentFilePath1);
            string decryptedContent2 = File.ReadAllText(decryptedContentFilePath2);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.True(File.Exists(decryptedContentFilePath2));
            Assert.Equal(content, decryptedContent1.Trim());
            Assert.Equal(content, decryptedContent2.Trim());

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void Verify_VerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.EncryptFileAndSign(contentFilePath, encryptedContentFilePath, publicKeyFilePath1, privateKeyFilePath1, password1);
            bool verified = pgp.VerifyFile(encryptedContentFilePath, publicKeyFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(verified);

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void Verify_VerifySignedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            pgp.SignFile(contentFilePath, signedContentFilePath, privateKeyFilePath1, password1);
            bool verified = pgp.VerifyFile(signedContentFilePath, publicKeyFilePath1);

            // Assert
            Assert.True(File.Exists(signedContentFilePath));
            Assert.True(verified);

            // Teardown
            Teardown();
        }
        #endregion File

        #region Stream
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptStream_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(publicKeyFilePath1, FileMode.Open))
                pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void SignStream_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.SignStream(inputFileStream, outputFileStream, privateKeyStream, password1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptStream_CreateEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream publicKeyStream2 = new FileStream(publicKeyFilePath2, FileMode.Open))
                pgp.EncryptStream(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptStreamAndSign_CreateEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, password1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void EncryptStreamAndSign_CreateEncryptedAndSignedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream publicKeyStream2 = new FileStream(publicKeyFilePath2, FileMode.Open))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 }, privateKeyStream, password1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptStream_DecryptEncryptedStream(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(publicKeyFilePath1, FileMode.Open))
                pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream);

            using (FileStream inputFileStream = new FileStream(encryptedContentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(decryptedContentFilePath1))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, password1);

            string decryptedContent = File.ReadAllText(decryptedContentFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.Equal(content, decryptedContent.Trim());

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptStream_DecryptEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream publicKeyStream2 = new FileStream(publicKeyFilePath2, FileMode.Open))
                pgp.EncryptStream(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (FileStream inputFileStream = new FileStream(encryptedContentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(decryptedContentFilePath1))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, password1);

            using (FileStream inputFileStream = new FileStream(encryptedContentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(decryptedContentFilePath2))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath2, FileMode.Open))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, password2);

            string decryptedContent1 = File.ReadAllText(decryptedContentFilePath1);
            string decryptedContent2 = File.ReadAllText(decryptedContentFilePath2);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.True(File.Exists(decryptedContentFilePath2));
            Assert.Equal(content, decryptedContent1.Trim());
            Assert.Equal(content, decryptedContent2.Trim());

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptStream_DecryptSignedAndEncryptedStream(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, password1);

            using (FileStream inputFileStream = new FileStream(encryptedContentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(decryptedContentFilePath1))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, password1);

            string decryptedContent = File.ReadAllText(decryptedContentFilePath1);

            bool verified = pgp.VerifyFile(encryptedContentFilePath, publicKeyFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.Equal(content, decryptedContent.Trim());
            Assert.True(verified);

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void DecryptStream_DecryptSignedAndEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream1 = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream publicKeyStream2 = new FileStream(publicKeyFilePath2, FileMode.Open))
                pgp.EncryptStream(inputFileStream, outputFileStream, new List<Stream>() { publicKeyStream1, publicKeyStream2 });

            using (FileStream inputFileStream = new FileStream(encryptedContentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(decryptedContentFilePath1))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, password1);

            using (FileStream inputFileStream = new FileStream(encryptedContentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(decryptedContentFilePath2))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath2, FileMode.Open))
                pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, password2);

            string decryptedContent1 = File.ReadAllText(decryptedContentFilePath1);
            string decryptedContent2 = File.ReadAllText(decryptedContentFilePath2);

            bool verified = pgp.VerifyFile(encryptedContentFilePath, publicKeyFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(File.Exists(decryptedContentFilePath1));
            Assert.True(File.Exists(decryptedContentFilePath2));
            Assert.Equal(content, decryptedContent1.Trim());
            Assert.Equal(content, decryptedContent2.Trim());
            Assert.True(verified);

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void Verify_VerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(encryptedContentFilePath))
            using (Stream publicKeyStream = new FileStream(publicKeyFilePath1, FileMode.Open))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, password1);

            bool verified = pgp.VerifyFile(encryptedContentFilePath, publicKeyFilePath1);

            // Assert
            Assert.True(File.Exists(encryptedContentFilePath));
            Assert.True(verified);

            // Teardown
            Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void Verify_VerifySignedStream(KeyType keyType)
        {
            // Arrange
            Arrange(keyType);
            PGP pgp = new PGP();
            bool verified = false;

            // Act
            using (FileStream inputFileStream = new FileStream(contentFilePath, FileMode.Open))
            using (Stream outputFileStream = File.Create(signedContentFilePath))
            using (Stream privateKeyStream = new FileStream(privateKeyFilePath1, FileMode.Open))
                pgp.SignStream(inputFileStream, outputFileStream, privateKeyStream, password1);

            using (FileStream inputFileStream = new FileStream(signedContentFilePath, FileMode.Open))
            using (Stream publicKeyStream = new FileStream(publicKeyFilePath1, FileMode.Open))
                verified = pgp.VerifyStream(inputFileStream, publicKeyStream);

            // Assert
            Assert.True(File.Exists(signedContentFilePath));
            Assert.True(verified);

            // Teardown
            Teardown();
        }
        #endregion Stream

        private void Arrange(KeyType keyType)
        {
            Directory.CreateDirectory(keyDirectory);
            Directory.CreateDirectory(contentDirectory);
            PGP pgp = new PGP();

            // Create keys
            if (keyType == KeyType.Generated)
            {
                pgp.GenerateKey(publicKeyFilePath1, privateKeyFilePath1, userName1, password1);
                pgp.GenerateKey(publicKeyFilePath2, privateKeyFilePath2, userName2, password2);
            }
            else if (keyType == KeyType.Known)
            {
                using (StreamWriter streamWriter = File.CreateText(publicKeyFilePath1))
                {
                    streamWriter.WriteLine(publicKey1);
                }

                using (StreamWriter streamWriter = File.CreateText(publicKeyFilePath2))
                {
                    streamWriter.WriteLine(publicKey2);
                }

                using (StreamWriter streamWriter = File.CreateText(privateKeyFilePath1))
                {
                    streamWriter.WriteLine(privatekey1);
                }

                using (StreamWriter streamWriter = File.CreateText(privateKeyFilePath2))
                {
                    streamWriter.WriteLine(privatekey2);
                }
            }

            // Create content file
            using (StreamWriter streamWriter = File.CreateText(contentFilePath))
            {
                streamWriter.WriteLine(content);
            }
        }

        private void Teardown()
        {
            // Remove keys
            if (File.Exists(publicKeyFilePath1))
            {
                File.Delete(publicKeyFilePath1);
            }

            if (File.Exists(privateKeyFilePath1))
            {
                File.Delete(privateKeyFilePath1);
            }

            if (File.Exists(publicKeyFilePath2))
            {
                File.Delete(publicKeyFilePath2);
            }

            if (File.Exists(privateKeyFilePath2))
            {
                File.Delete(privateKeyFilePath2);
            }

            if (Directory.Exists(keyDirectory))
            {
                Directory.Delete(keyDirectory);
            }

            // Remove content
            if (File.Exists(contentFilePath))
            {
                File.Delete(contentFilePath);
            }

            if (File.Exists(encryptedContentFilePath))
            {
                File.Delete(encryptedContentFilePath);
            }

            if (File.Exists(signedContentFilePath))
            {
                File.Delete(signedContentFilePath);
            }

            if (File.Exists(decryptedContentFilePath1))
            {
                File.Delete(decryptedContentFilePath1);
            }

            if (File.Exists(decryptedContentFilePath2))
            {
                File.Delete(decryptedContentFilePath2);
            }

            if (Directory.Exists(contentDirectory))
            {
                Directory.Delete(contentDirectory);
            }
        }

        public enum KeyType
        {
            Generated,
            Known
        }

        // Content
        const string contentDirectory = "./Content/";
        const string content = "The quick brown fox jumps over the lazy dog";
        const string contentFilePath = contentDirectory + "content.txt";
        const string encryptedContentFilePath = contentDirectory + "encryptedContent.pgp";
        const string signedContentFilePath = contentDirectory + "signedContent.pgp";
        const string decryptedContentFilePath1 = contentDirectory + "decryptedContent1.txt";
        const string decryptedContentFilePath2 = contentDirectory + "decryptedContent2.txt";
        const string encryptedContent1 = @"-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

wcBMA+cxhM+dKt4UAQgA6MiSXq2KSOlAsGFl2DrCp/j7CIeFBSxc/elikmS0
9jvYV8yhTZ6F3N1Cj1tDQZ18d7Ih5npRkCXlCMKijTRJ6T4gChQ/rIAtA1hr
tSjz8UzHFetFxiXCacWUNK+Q1WRG7CKfClvF9tOBrG6WmKwkY+KzbDQ0vRzQ
1JRnHAfJ++fq5y3mJIlUoCNhgYMl5vDvr6rkGW7bFjFfB6amLdIHZn9Tc3GV
jRG6v5MxqAppEsqIhEgr17/6qSslU/IFTokNNsd0OTGTzTejmY49SPM3O6e9
Ou2hqUPPRovNuhqOtys6HpMU+mesprrdx6a7OeWnlDvCkg3N37LLpssyHqum
kNJjAaHUdUGuuQ8ZCtuu7NC/LdfCGu+WT0iQAR9kdLTwNOq1TgsYu68TEX1u
Dq3YVTdbdAF/uURDx4aexQDVTq8IDk32FwVSaES6PG5qCgR0RCkwkJGxruhT
sZg/AsVo3z+/sr7a
=4Wwg
-----END PGP MESSAGE-----";
        const string encryptedContent2 = @"-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

wcBMA9QtMjxDkm//AQf6Aqxd0fr81dBjxP892DEtC9Nwq2AXFgBAnAlhTGIr
8zPrtr12V5V6aTOZ0IChldtsaEGwxVrodFhqWO4WKlFrpVon86RglOednHU/
/sJNbdsnW3t8dUbD8k8V+5pkba+oX6iklvzv8hpqAEMc7Gwp7fMcDPF00BkY
mhIBvZXpCbLRtQt/K4qo3kpRqZDJSWKGtGPtXDGtx7duCxR41ArleQjfGyxN
Be5bWPu0/gZWMkew62PFTDIqeBfRR7+V1PMRhwL0WJdgOqhRoDkNQhUPJ7aa
ALSy//blnbktrSZrR7vWo3lm2ZGFl0uzcpBM3pcFFMssieOPi+E7IovfZTW0
O9JjAUTVXka99zj8wPlezPqUsekTIhgVw5vso4gJTz3DsJR0jtTIWczgp5+U
1hay6pEQUCGasIB5OWQImpKmTNEHmv+jvXskuk4kuPy7gqOiWcN34XTmGGbz
MFHwXEtblMhDz7ni
=navA
-----END PGP MESSAGE-----";

        // Keys
        const string keyDirectory = "./Keys/";
        const string publicKeyFilePath1 = keyDirectory + "publicKey1.asc";
        const string publicKeyFilePath2 = keyDirectory + "publicKey2.asc";
        const string privateKeyFilePath1 = keyDirectory + "privateKey1.asc";
        const string privateKeyFilePath2 = keyDirectory + "privateKey2.asc";
        const string userName1 = "email1@email.com";
        const string userName2 = "email2@email.com";
        const string password1 = "password1";
        const string password2 = "password2";

        // Known keys, generated using https://pgpkeygen.com/
        const string publicKey1 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xo0EXRzQ9gEEALWy0pmWiNwti765q5l/cgohqa5fKBZWy2VggB8YlLNSGaiR4Esd
Ya0+SSkwe0C3O9xjzUlQA/0SGYelxjgYhxqTyvLiVKKTx6HE1FW6PPrYMK4+GQaH
SfhO5ILLqXx0/o7XF77qSmxdrcQrIwNhdeOwDBDOrwLWDuU+Gx/F9AU9ABEBAAHN
I2VtYWlsMUBlbWFpbC5jb20gPGVtYWlsMUBlbWFpbC5jb20+wq0EEwEKABcFAl0c
0PYCGy8DCwkHAxUKCAIeAQIXgAAKCRAy61veQBr1zRx8A/43SUeO5lGjksMbZuqp
fiJFdjd3aT94jz7oukfUL/t+ToVtxRRSTr6aoYVclK21TP797zme86zsmM3fUKzO
nVCs4V4E9c7lz69hd2+PBhDX29a7fywFWOQ5dAavuHUAw8akLZdY7sWh720Gbh8Q
3GRdrUry78nmkAWuw8JBh71uX86NBF0c0PYBBADW3E+IuxoDxc1CSJBL8iLc4A9L
3FpWeifBbq5PCpjYcqodb1FvD5eaqYgqf5/hPQLdRP/XRHtKKkph+XdF5Wrx0AMC
sEgr6JZ3SicobLev028DADYugJcZ9E1T/nkkkggamQBX5ryxB6X8se0m27QTd06n
KIhN67qCX/Gi+3UkmwARAQABwsCDBBgBCgAPBQJdHND2BQkPCZwAAhsuAKgJEDLr
W95AGvXNnSAEGQEKAAYFAl0c0PYACgkQHCBL6iCIoI+EhQP+OgbEfsQwixiyVQaG
1D+RSAGAnARX2Y+VatAtRsWuEXNYeNjFsPDMRbgtoCfrAlQoL0wXQXu+TXOu9xkL
u3hq4Nd8+fvvE1znc1zT7Ie1Tb20luA7Qzk3lQV4w2nxpXL3hl7JN1KxmPwanrQv
bT99eh9lhceoQHls/g1+sjOtQ4Kr1wQAnUMopnAavdlnfpJYXTqHH6QI4uBYscNH
ZHa5OdLgFBzBx+IGvYpDZzTjxuAmbVvQZIkJi4iI0xua/ER/AJIdYgSUTbKT7nif
f8neNHVvJGTF1iYoORMFrQEjnYPwRaEnzMpLkCryBsGFjYfj1X2wrzNL5dEzU97M
R2qeFsfC3szOjQRdHND2AQQAp1m2xMs34pmeVzGqbmRcoASe+MHazJyv+L+XhEF0
OxThH4NKLJLXotib9KXZlgqfiETgmRvoLeQvBu2f/5Nf5TgGITcS8/0jyvolwv+9
IRPxXRBXbk3H89z5UqVFa2FkEnS21wQUMRYqUEzO1n04ImhAWOUDF3b8eOT1q2+A
HnMAEQEAAcLAgwQYAQoADwUCXRzQ9gUJDwmcAAIbLgCoCRAy61veQBr1zZ0gBBkB
CgAGBQJdHND2AAoJEEdOvSYcuM90w1YD/3XCcndLA4OIF7cJlo1DbPkN3cwtldvT
vyvf9n7G5epB99/wNjDrWzzFXWU+3oOOwnnQXk9oZoWOPmMp02OlZW7s3WLWj5ZQ
0RoEzM3cQRdpTU1oX02zNKoMGcHY5Tfiacfvr/EZx3ElsyZ81zIR0HtyXMwRrgTg
A4KsnnILrp6JpVkD/20JllnAfq7xIqGpQCFCs1CxYYDEfEuqxcQf+wpdICG6FqRn
P4IOoqsVnY2EEHwdr9VjKyf6L+Pd2PLou8pWCu6rF/M3zIjAwzzPsJ5/AlINTql0
b8xSWNM02DrVx932kcSOx4k8BaZ0IiSwzny4xZEoOIPKK8SZ+EZeZaeopZ7h
=O3ub
-----END PGP PUBLIC KEY BLOCK-----";
        const string publicKey2 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xo0EXRzR8gEEAOJguWTfef08UottAIqsBxYh0Cea7QF4toOdSCOXwT70pY+uiwVj
gMgd1IqI8/uZg2orYsI2+6SYUjyNbYXOMIBgLt7LNz2Xu//RCqcVgdhpgusXnQoI
ru+BoT1H0IcgGAmwQ1MxvvTX5MmcDpzRBgNkpfQIsohmnYsX46GzYUpjABEBAAHN
I2VtYWlsMkBlbWFpbC5jb20gPGVtYWlsMkBlbWFpbC5jb20+wq0EEwEKABcFAl0c
0fICGy8DCwkHAxUKCAIeAQIXgAAKCRDHOc/0fnhNpuFhBAChzcCOwhGnNZTV2xFB
8CXbAt6mEfuxgcVdiKEKNZvvk75HJKmN0/5hW9ubfIGpu4oxsfFV7DEElKpCoj6K
513kM9J32wmfzx49mRJYXsMFeResF3XS1qN7JfY0o/vrI3HZAFwA2xddkK4NkXl+
r1TXO+VrJrW4FAc34a2OCGb5w86NBF0c0fIBBADSE2B/pYRFSSVmbuqQM+37BZhm
Hwk1aXlHVpX4IKV65SzVID9qrub2PrwClRdm1q+1wuaiEaWsT2obYRXLaXfsWb6F
3g9gumIoMd7k1T8rUsmVgddroyegtPsEFSNcSGtFKpBVwhMznTMqBkr4QMLxAyw0
fOSwag0Rc2ipBW+i/wARAQABwsCDBBgBCgAPBQJdHNHyBQkPCZwAAhsuAKgJEMc5
z/R+eE2mnSAEGQEKAAYFAl0c0fIACgkQUI7UIwZpecWdvwP9FekQEnaxm3i+Sevv
B8MQlIzuypOWBIqTWx8Xcw/ldkFZDfujFHBIvLULMXNxO8rrsRXii5w1gR0xVj5A
mxTp6v+q2z+fmRoVr0Ym/r/chNlkbR4Jle+QckPeSnhKMZEfLmB4D4K6tX4CUCSF
EoIx6oWWeIbTdeNCQnHvbGALpEkDIwQAx0ihTWXggVZXaCtyOFVJKwCK8EPKu3pR
vK64vzoNqlqxd7F8Qhzo971aR9vTOvS4CV78ovQFX02TZGHocRWZx1mGdrlVPZWp
OlzHR0vT0psBSvaFWqkaifOScEQ0ATKguJNvo+kHOKBW3p/F6zrzqcG94RCPkHf2
MrSSQubDtOfOjQRdHNHyAQQAu5YHRDMFBLa7afjPtkMooybqM1KSeC62jByXReRT
EfVIgRDdI+1p19z/hPBz//OSU0kN6ePrhYSlIvhT74Nk8CTpvAwpS1791SC7mwxU
wZK5jNMi5HrfOlGwlhasdSe+v3xiSbSkHEtwPscBbyBWSqqGZbZIkk1OfjtBcK3P
55kAEQEAAcLAgwQYAQoADwUCXRzR8gUJDwmcAAIbLgCoCRDHOc/0fnhNpp0gBBkB
CgAGBQJdHNHyAAoJEEbXCPn6ISugs+kD/340wN26UWPXEJUugy+yjpixYkU3T6vS
V0QzF3188TEUhrVd6TBVea7HBQOsg+aSZQTrEICfcmif6zmJ9r+6Q5BNuIc8wy7G
zkBJ7kR/XyfAHN5MNLfdBnHSZZqRwIbrm4rVNIOjXhLVUNaOF3v9wlor7JNVoXP/
+3yMMp8k32a28HUEAN988ZbipEZFyZjhZWPQbpuNA0LxRiqV4HMoCiJ+jBM3lGVp
O3IEvHTXyUErcgSBekr3BhIuHTHwt9RWTVNWBku8UsX9Ao1M8vRWimNwIlGdBrIT
iSJGzF6qhiiorxaJkMNx7xDgxQFZgHiihjIsolKego98NLI8e9j7+6zOHR0f
=lgvU
-----END PGP PUBLIC KEY BLOCK-----";
        const string privatekey1 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

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
BaZ0IiSwzny4xZEoOIPKK8SZ+EZeZaeopZ7h
=i6tW
-----END PGP PRIVATE KEY BLOCK-----";
        const string privatekey2 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

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
AVmAeKKGMiyiUp6Cj3w0sjx72Pv7rM4dHR8=
=dUJo
-----END PGP PRIVATE KEY BLOCK-----";
    }
}
