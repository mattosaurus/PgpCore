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

        // Known keys, generated using https://wp2pgpmail.com/pgp-key-generator/
        const string publicKey1 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

xsBNBFzPBNoBCACzrqGe/6S/SkXOTM8e3xFg6cITX5qXDk+kOzHHIDVwr6sH
xhBKEJID0M1LfxWQ7E3lvhx7rhcCf/OBxSLosMo/YiGbKIwIQ1YCppcr+i1c
Pm/zQbfHsMbaLohjo2xzwJ7421y1yuWRW+uIc9BqBB85CpwulI9pjQj4T9D9
WTkT+51+S6EKVXyPFtDIraPAe4PZTkjp3pQareL0h5XJ2alrNbzs7GsNjTQU
tall8TpAjWHKw3PWC1nBY4Vx0sC98zaSC4J1hNvACHnzL5qyGnUZsv0fmwpz
XC2TKD/Lrzd/zTQxC7Eq3eGt46ksld2TlHxavv5lbKvNwA3Si+ZDe6klABEB
AAHNHFRlc3QgVXNlciA8ZW1haWwxQGVtYWlsLmNvbT7CwHUEEAEIACkFAlzP
BNoGCwkHCAMCCRBK0Tg8RNvQ7AQVCAoCAxYCAQIZAQIbAwIeAQAAa5cIAIDr
F7pNjjOmIqt5a/S+xVomaTFLXaM4pumsZIrwhlUxfLyE8UcwclX96Z2iLCzf
tJPIQELRlFT8C+2lJu9905AX5mFqyljHUTtlwO27Ndsb5niHy+TJtSute0qa
Cs25uoAxVOE/cs1j0qsP6xuoL7VEyHUO8kbOxl8V3utnZaLkdzyl67c8i4Ku
HLbwtZFfita6e5Nhf2wRJW6wRA2bay+HT83Z8wYLSKC/WwUZHOfM/o5LW0My
Cg0MgTCVNSyusiHzS3U3N49SjyXKsgVGw4BEKo1jzoUJuBsPOYmbmj6lwb8v
+Wc8ScAFEqFF57HIe9UawNT9N74YoMY6dbS1YnLOwE0EXM8E2gEIAPlAH1wg
Z8l5VD/DkN7yY+wHrt03RFrOJ37bABxQWX3nm9bqeuJOdSRRqgwcZDzpijOR
PY82f9RiOA9e8hVZmhNaqDjtI0BrUe4Fu3WWcT5SJbA4svgVCU3v0FsK/HeR
3no8mAh9yol/TPPQTsScOuAToOEVkP7+0cTPaMKQHgMgSJwbu1qMRXW3vhqS
MTwsNasw1RFX03WHtgAEnRnhxgSFMy0eDW5nSZhdvMm/1F2dB9zuBi/5gJX6
yftz9Z3lL+nhnRAGWMKGzS9LeX/WtXUZgA+r6ZyxatD93sLUruWDr0yihEcG
zTPi5RZ8+ZsmNi+W4NDL0qqpMFYbGh6U9WcAEQEAAcLAXwQYAQgAEwUCXM8E
2gkQStE4PETb0OwCGwwAAJJgB/9/iybf1GXElCjwdt3rqyo8eN2r6klZ8EDu
sqlMsFCGjbSSkoJtp38E6dbcAwZsvq7EnfacMiyBQg0Q6ZjuCuVGRAbH4Y6Z
BYwyoWoM4CkdFrUirzROg4JEe+SX/OjyuMh5HY9kj91H1uUSQEHvf3ItQGFU
P7rmdsiZfxneR5HM7ydnOJU7Mdb30U2JS9UIGb3eIkDB0U8OTpkHA6qM4wG5
s86AvESpZCQySKHT+yp2kI1pza2I8l6C8K5WPG424Hg+3be4p4T3F7I5ECR0
gXhgwGfxg6Qo0sKl00iVNt35ZIvj9e9Snk/6D0oDXBZUb4kc48gDTaGkuUQ6
wO9qNilP
=38dH
-----END PGP PUBLIC KEY BLOCK-----";
        const string publicKey2 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

xsBNBFzPArcBCADObQOISEUExywwRpniqEB6Z89MThbce3OvUSc+xIMuyCxS
MjZ2T4Df45lTLpDwURDieF+uhCINvtnMlGQ2k0FBgKUA0YXdfTz7VMvup/3B
mYNcHaouQrpERhYl/RSf0qeMQ9kPTeVxgAp9aCB3K/gitxFpdaddhv3lJGQn
2rjebfYNeBRDHfezZnWgAOQKEyFTCyNdhcKFs1yPu47YOkCq+eJWWU5KuxEm
En7WOVPvCxVDF2Nzeh/UwYr7/pEQvLulSO+vaSTBKaD0PTKBjkiVSLMcJxSo
xFJQaqU+uiwxAnAKW1J4+IpNaBZ3DKjsP9zD7TVJ5VGBVZosgqJj7VALABEB
AAHNHFRlc3QgVXNlciA8ZW1haWwyQGVtYWlsLmNvbT7CwHUEEAEIACkFAlzP
ArcGCwkHCAMCCRD5fsN4GWPvqwQVCAoCAxYCAQIZAQIbAwIeAQAAedUIALjt
MYLSMUvm/XYedfE3wgQs4RtpxwijKQNzBS/C2thDJ8IIzO6+ougeF70zORH+
GF14E65KBStfCyqdCSmfE8t3NvlkDlU6OiHbai8R9qhnX7kkoF/byTVnkg4f
augxMKn9Rd5G7ri8plMRssORIBl/IqGTPfWxojaxEVEGwzoMf13pMpGRwJj4
pnyboRkWZKwBHcBpqyyWmD+GcllrTMdt6fprpB7l1WfOAchHH2pf7eIsHA/E
gaU56if4XwtohYJtE9VX/LyclOpJrYf9JDr28jQkSC3Nub5lMx73OfkzIkvS
tG1IQYJm6O/8pUJerJwnR7pOX/T61ZU+KRZyGFXOwE0EXM8CtwEIALC4splo
w5SD4/rE3feijEJYW25G+N5hLrJJ6pLZITbUIxZG1cZ4QGzbJDVf+KdWHwB5
luwce7MrZMcZ1xFQtuTbnmK7Prb4P9Z3pkL1ZY7VZ7R4LKDTulRtg0jwnU+S
STNEWtztWugjzHWDjmEK0Np7sG5buTfMyIkC5Rw73NXyRUB84vOZKeCe+2SJ
Uy0+qZO2hhYDaUH0jYreMD7DCcNGh7u4RZMNZo4IC4QNhlBOTeoNRmp0w03q
LyIYwX8xpjsYIC0hXfufDSkjxYxgBUL+XqJrp7jeGW4uxqaTZJ1i8afxX1tV
e2NOQqkx4wrOJdRsWXBrNrq6VDXGOzthjTMAEQEAAcLAXwQYAQgAEwUCXM8C
twkQ+X7DeBlj76sCGwwAACGGB/96L27YWGgX58A3gzeV8DfMdlSPlKj4HsnR
pt02fLWk4grScLlVNg8Pksp1Gs1NK9yJWIdG0XoFxS8+XV9f+faBcIiOWSWe
MrU8J8SJBfIqV8eBdtIXRVYHJkqmi9/Q0fMYyKf6zAiW7IPBASCrHPT55BpJ
v67Vua/q5ikNCOrxq+fyAdXFnGm4DILFPRgFvb7HYBZtSBlJ8mQE41tWLhzM
0y7/ZzeO33B8LFXaXfE8DCTTVjuO5v18Y2h18csZI2puSK0AMK25cNu+NAy1
XuAYO7yDVdCWch+vExvkTa9+AO6hAEnS41O/POOK/fmVLubxpXMpLFaz7Bcj
YVB9IK/y
=8mNG
-----END PGP PUBLIC KEY BLOCK-----";
        const string privatekey1 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

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
72o2KU8=
=D6Bw
-----END PGP PRIVATE KEY BLOCK-----";
        const string privatekey2 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

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
fSCv8g==
=/200
-----END PGP PRIVATE KEY BLOCK-----";
    }
}
