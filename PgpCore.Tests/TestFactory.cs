using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Tests
{
    public class TestFactory
    {
        private string _uniqueIdentifier;
        private string _userName;
        private string _password;
        private byte[] _symmetricKey;

        public TestFactory()
        {
            _uniqueIdentifier = Guid.NewGuid().ToString();
        }

        public TestFactory(string uniqueIdentifier)
        {
            _uniqueIdentifier = uniqueIdentifier;
        }

        public string ContentDirectory => $"{Constants.CONTENTBASEDIRECTORY}{_uniqueIdentifier}/";

        public string KeyDirectory => $"{Constants.KEYBASEDIRECTORY}{_uniqueIdentifier}/";

        public string Content => Constants.CONTENT;

        private string ContentFilePath => $"{ContentDirectory}{Constants.CONTENTFILENAME}";

        public FileInfo ContentFileInfo => new FileInfo(ContentFilePath);

        public Stream ContentStream => GetFileStream(ContentFileInfo);

        private string EncryptedContentFilePath => $"{ContentDirectory}{Constants.ENCRYPTEDCONTENTFILENAME}";

        public FileInfo EncryptedContentFileInfo => new FileInfo(EncryptedContentFilePath);

        public string EncryptedContent => File.ReadAllText(EncryptedContentFilePath);

        public Stream EncryptedContentStream => GetFileStream(EncryptedContentFileInfo);

        private string SignedContentFilePath => $"{ContentDirectory}{Constants.SIGNEDCONTENTFILENAME}";

        public FileInfo SignedContentFileInfo => new FileInfo(SignedContentFilePath);

        public string SignedContent => File.ReadAllText(SignedContentFilePath);

        public Stream SignedContentStream => GetFileStream(SignedContentFileInfo);

        private string DecryptedContentFilePath => $"{ContentDirectory}{Constants.DECRYPTEDCONTENTFILENAME}";

        public FileInfo DecryptedContentFileInfo => new FileInfo(DecryptedContentFilePath);

        public string DecryptedContent => File.ReadAllText(DecryptedContentFilePath);

        public Stream DecryptedContentStream => GetFileStream(DecryptedContentFileInfo);

        private string PrivateKeyFilePath => $"{KeyDirectory}{Constants.PRIVATEKEYFILENAME}";

        public FileInfo PrivateKeyFileInfo => new FileInfo(PrivateKeyFilePath);

        public string PrivateKey => File.ReadAllText(PrivateKeyFilePath);

        public Stream PrivateKeyStream => GetFileStream(PrivateKeyFileInfo);

        private string PublicKeyFilePath => $"{KeyDirectory}{Constants.PUBLICKEYFILENAME}";

        public FileInfo PublicKeyFileInfo => new FileInfo(PublicKeyFilePath);

        public string PublicKey => File.ReadAllText(PublicKeyFilePath);

        public Stream PublicKeyStream => GetFileStream(PublicKeyFileInfo);

        public string UserName => _userName != null ? _userName : $"{_uniqueIdentifier}@email.com" ;

        public string Password => _password != null ? _password : _uniqueIdentifier;
        
        public byte[] SymmetricKey => _symmetricKey;

        public void Arrange(KeyType keyType)
        {
            Arrange();
            PGP pgp = new PGP();

            switch (keyType)
            {
                // Create keys
                case KeyType.Generated:
                    pgp.GenerateKey(PublicKeyFileInfo, PrivateKeyFileInfo, UserName, Password);
                    break;
                case KeyType.Symmetric:
                    _symmetricKey = Encoding.UTF8.GetBytes(Constants.PASSWORD1);
                    
                    using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                    {
                        streamWriter.WriteLine(Constants.PUBLICKEY1);
                    }

                    using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                    {
                        streamWriter.WriteLine(Constants.PRIVATEKEY1);
                    }

                    _userName = Constants.USERNAME1;
                    _password = Constants.PASSWORD1;
                    break;
                case KeyType.Known:
                {
                    using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                    {
                        streamWriter.WriteLine(Constants.PUBLICKEY1);
                    }

                    using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                    {
                        streamWriter.WriteLine(Constants.PRIVATEKEY1);
                    }

                    _userName = Constants.USERNAME1;
                    _password = Constants.PASSWORD1;
                    break;
                }
                case KeyType.KnownGpg:
                {
                    using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                    {
                        streamWriter.WriteLine(Constants.PUBLICGPGKEY1);
                    }

                    using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                    {
                        streamWriter.WriteLine(Constants.PRIVATEGPGKEY1);
                    }

                    _userName = Constants.USERNAME1;
                    _password = Constants.PASSWORD1;
                    break;
                }
            }
        }

        public async Task ArrangeAsync(KeyType keyType)
        {
            Arrange();
            PGP pgp = new PGP();

            switch (keyType)
            {
                // Create keys
                case KeyType.Generated:
                    await pgp.GenerateKeyAsync(PublicKeyFileInfo, PrivateKeyFileInfo, UserName, Password);
                    break;
                case KeyType.Symmetric:
                    _symmetricKey = Encoding.UTF8.GetBytes(Constants.PASSWORD1);
                    
                    await using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                    {
                        await streamWriter.WriteLineAsync(Constants.PUBLICKEY1);
                    }

                    await using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                    {
                        await streamWriter.WriteLineAsync(Constants.PRIVATEKEY1);
                    }

                    _userName = Constants.USERNAME1;
                    _password = Constants.PASSWORD1;
                    break;
                case KeyType.Known:
                {
                    await using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                    {
                        await streamWriter.WriteLineAsync(Constants.PUBLICKEY1);
                    }

                    await using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                    {
                        await streamWriter.WriteLineAsync(Constants.PRIVATEKEY1);
                    }

                    _userName = Constants.USERNAME1;
                    _password = Constants.PASSWORD1;
                    break;
                }
                case KeyType.KnownGpg:
                {
                    using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                    {
                        await streamWriter.WriteLineAsync(Constants.PUBLICGPGKEY1);
                    }

                    using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                    {
                        await streamWriter.WriteLineAsync(Constants.PRIVATEGPGKEY1);
                    }

                    _userName = Constants.USERNAME1;
                    _password = Constants.PASSWORD1;
                    break;
                }
            }
        }

        public void Arrange(FileType fileType)
        {
            Arrange();

            switch (fileType)
            {
                // Create content file
                case FileType.Known:
                {
                    using (StreamWriter streamWriter = ContentFileInfo.CreateText())
                    {
                        streamWriter.Write(Constants.CONTENT);
                    }
                    break;
                }
                case FileType.GeneratedMedium:
                    CreateRandomFile(ContentFilePath, 300);
                    break;
                case FileType.GeneratedLarge:
                    CreateRandomFile(ContentFilePath, 5000);
                    break;
            }
        }

        public async Task ArrangeAsync(FileType fileType)
        {
            Arrange();

            switch (fileType)
            {
                // Create content file
                case FileType.Known:
                {
                    using (StreamWriter streamWriter = ContentFileInfo.CreateText())
                    {
                        await streamWriter.WriteAsync(Constants.CONTENT);
                    }
                    break;
                }
                case FileType.GeneratedMedium:
                    await CreateRandomFileAsync(ContentFilePath, 300);
                    break;
                case FileType.GeneratedLarge:
                    await CreateRandomFileAsync(ContentFilePath, 5000);
                    break;
            }
        }

        public void Arrange(KeyType keyType, FileType fileType)
        {
            Arrange();
            Arrange(keyType);
            Arrange(fileType);
        }

        public async Task ArrangeAsync(KeyType keyType, FileType fileType)
        {
            Arrange();
            await ArrangeAsync(keyType);
            await ArrangeAsync(fileType);
        }

        public void Arrange()
        {
            if (!Directory.Exists(ContentDirectory))
            {
                Directory.CreateDirectory(ContentDirectory);
            }

            if (!Directory.Exists(KeyDirectory))
            {
                Directory.CreateDirectory(KeyDirectory);
            }
        }

        public void Teardown()
        {
            if (Directory.Exists(ContentDirectory))
            {
                Directory.Delete(ContentDirectory, true);
            }

            if (Directory.Exists(KeyDirectory))
            {
                Directory.Delete(KeyDirectory, true);
            }
        }

        private void CreateRandomFile(string filePath, int sizeInMb)
        {
            // Note: block size must be a factor of 1MB to avoid rounding errors
            const int blockSize = 1024 * 8;
            const int blocksPerMb = (1024 * 1024) / blockSize;

            byte[] data = new byte[blockSize];

            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                using (FileStream stream = File.OpenWrite(filePath))
                {
                    for (int i = 0; i < sizeInMb * blocksPerMb; i++)
                    {
                        crypto.GetBytes(data);
                        stream.Write(data, 0, data.Length);
                    }
                }
            }
        }

        private async Task CreateRandomFileAsync(string filePath, int sizeInMb)
        {
            // Note: block size must be a factor of 1MB to avoid rounding errors
            const int blockSize = 1024 * 8;
            const int blocksPerMb = (1024 * 1024) / blockSize;

            byte[] data = new byte[blockSize];

            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                using (FileStream stream = File.OpenWrite(filePath))
                {
                    for (int i = 0; i < sizeInMb * blocksPerMb; i++)
                    {
                        crypto.GetBytes(data);
                        await stream.WriteAsync(data, 0, data.Length);
                    }
                }
            }
        }

        private Stream GetFileStream(FileInfo fileInfo)
        {
            Stream outputStream = new MemoryStream();
            using (FileStream fileStream = fileInfo.OpenRead())
            {
                fileStream.CopyTo(outputStream);
            }

            outputStream.Position = 0;
            outputStream.Seek(0, SeekOrigin.Begin);
            return outputStream;
        }
    }

    public enum KeyType
    {
        Generated,
        Known,
        KnownGpg,
        Symmetric
    }

    public enum FileType
    {
        GeneratedMedium,
        GeneratedLarge,
        Known
    }
}