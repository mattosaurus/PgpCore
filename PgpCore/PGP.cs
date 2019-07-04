using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public enum PGPFileType { Binary, Text, UTF8 }

    public class PGP : IDisposable
    {
        public static readonly PGP Instance = new PGP();

        private const int BufferSize = 0x10000;

        public CompressionAlgorithmTag CompressionAlgorithm
        {
            get;
            set;
        }

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm
        {
            get;
            set;
        }

        public int PgpSignatureType
        {
            get;
            set;
        }

        public PublicKeyAlgorithmTag PublicKeyAlgorithm
        {
            get;
            set;
        }
        public PGPFileType FileType
        {
            get;
            set;
        }

        #region Constructor

        public PGP()
        {
            CompressionAlgorithm = CompressionAlgorithmTag.Uncompressed;
            SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.TripleDes;
            PgpSignatureType = PgpSignature.DefaultCertification;
            PublicKeyAlgorithm = PublicKeyAlgorithmTag.RsaGeneral;
            FileType = PGPFileType.Binary;
        }

        #endregion Constructor

        #region Encrypt

        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, publicKeyFilePath, armor, withIntegrityCheck));
        }

        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, IEnumerable<string> publicKeyFilePaths,
            bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, publicKeyFilePaths, armor, withIntegrityCheck));
        }

        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream,
            bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptStream(inputStream, outputStream, publicKeyStream, armor, withIntegrityCheck));
        }

        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams,
            bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptStream(inputStream, outputStream, publicKeyStreams, armor, withIntegrityCheck));
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        public void EncryptFile(
            string inputFilePath,
            string outputFilePath,
            string publicKeyFilePath,
            bool armor = true,
            bool withIntegrityCheck = true)
        {
            EncryptFile(inputFilePath, outputFilePath, new [] {publicKeyFilePath}, armor, withIntegrityCheck);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePaths"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        public void EncryptFile(
            string inputFilePath,
            string outputFilePath,
            IEnumerable<string> publicKeyFilePaths,
            bool armor = true,
            bool withIntegrityCheck = true)
        {
            //Avoid multiple enumerations of 'publicKeyFilePaths'
            string[] publicKeys = publicKeyFilePaths.ToArray();

            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
            foreach (string publicKeyFilePath in publicKeys)
            {
                if(String.IsNullOrEmpty(publicKeyFilePath))
                    throw new ArgumentException(nameof(publicKeyFilePath));
                if (!File.Exists(publicKeyFilePath))
                    throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", publicKeyFilePath));
            }

            using (MemoryStream @out = new MemoryStream())
            {
                if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
                {
                    PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithm);
                    Utilities.WriteFileToLiteralData(comData.Open(@out), FileTypeToChar(), new FileInfo(inputFilePath));
                    comData.Close();
                }
                else
                    Utilities.WriteFileToLiteralData(@out, FileTypeToChar(), new FileInfo(inputFilePath));

                PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

                foreach (string publicKeyFilePath in publicKeys)
                {
                    using (Stream pkStream = File.OpenRead(publicKeyFilePath))
                    {
                        pk.AddMethod(Utilities.ReadPublicKey(pkStream));
                    }
                }

                byte[] bytes = @out.ToArray();

                using (Stream outStream = File.Create(outputFilePath))
                {
                    if (armor)
                    {
                        using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outStream))
                        {
                            using (Stream armoredOutStream = pk.Open(armoredStream, bytes.Length))
                            {
                                armoredOutStream.Write(bytes, 0, bytes.Length);
                            }
                        }
                    }
                    else
                    {
                        using (Stream plainStream = pk.Open(outStream, bytes.Length))
                        {
                            plainStream.Write(bytes, 0, bytes.Length);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="publicKeyStream"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        public void EncryptStream(
            Stream inputStream,
            Stream outputStream,
            Stream publicKeyStream,
            bool armor = true,
            bool withIntegrityCheck = true)
        {
            EncryptStream(inputStream, outputStream, new[] { publicKeyStream }, armor, withIntegrityCheck);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="publicKeyFilePaths"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        public void EncryptStream(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams, bool armor = true, bool withIntegrityCheck = true)
        {
            //Avoid multiple enumerations of 'publicKeyFilePaths'
            Stream[] publicKeys = publicKeyStreams.ToArray();

            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            foreach (Stream publicKey in publicKeys)
            {
                if (publicKey == null)
                    throw new ArgumentException("PublicKeyStream");
            }

            using (MemoryStream @out = new MemoryStream())
            {
                if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
                {
                    PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithm);
                    Utilities.WriteStreamToLiteralData(comData.Open(@out), FileTypeToChar(), inputStream, "name");
                    comData.Close();
                }
                else
                    Utilities.WriteStreamToLiteralData(@out, FileTypeToChar(), inputStream, "name");

                PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

                foreach (Stream publicKey in publicKeys)
                {
                    pk.AddMethod(Utilities.ReadPublicKey(publicKey));
                }

                byte[] bytes = @out.ToArray();

                if (armor)
                {
                    using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                    {
                        using (Stream armoredOutStream = pk.Open(armoredStream, bytes.Length))
                        {
                            armoredOutStream.Write(bytes, 0, bytes.Length);
                        }
                    }
                }
                else
                {
                    using (Stream plainStream = pk.Open(outputStream, bytes.Length))
                    {
                        plainStream.Write(bytes, 0, bytes.Length);
                    }
                }
            }
        }

        #endregion Encrypt

        #region Encrypt and Sign

        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath,
            string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFileAndSign(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase, armor, withIntegrityCheck));
        }

        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, IEnumerable<string> publicKeyFilePaths, string privateKeyFilePath,
            string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFileAndSign(inputFilePath, outputFilePath, publicKeyFilePaths, privateKeyFilePath, passPhrase, armor, withIntegrityCheck));
        }

        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptStreamAndSign(inputStream, outputStream, publicKeyStream, privateKeyStream, passPhrase, armor, withIntegrityCheck));
        }

        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams, Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptStreamAndSign(inputStream, outputStream, publicKeyStreams, privateKeyStream, passPhrase, armor, withIntegrityCheck));
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            EncryptFileAndSign(inputFilePath, outputFilePath, new[] { publicKeyFilePath }, privateKeyFilePath, passPhrase, armor, withIntegrityCheck);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePaths"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, IEnumerable<string> publicKeyFilePaths,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            //Avoid multiple enumerations of 'publicKeyFilePaths'
            string[] publicKeys = publicKeyFilePaths.ToArray();

            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                passPhrase = String.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFilePath));

            foreach (string publicKeyFilePath in publicKeys)
            {
                if (String.IsNullOrEmpty(publicKeyFilePath))
                    throw new ArgumentException(nameof(publicKeyFilePath));
                if (!File.Exists(publicKeyFilePath))
                    throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", publicKeyFilePath));
            }

            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKeyFilePaths, privateKeyFilePath, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(inputFilePath, armoredOutputStream, encryptionKeys, withIntegrityCheck);
                    }
                }
                else
                    OutputEncrypted(inputFilePath, outputStream, encryptionKeys, withIntegrityCheck);
            }
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="publicKeyStream"></param>
        /// <param name="privateKeyStream"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, Stream publicKeyStream,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            EncryptStreamAndSign(inputStream, outputStream, new[] { publicKeyStream }, privateKeyStream, passPhrase, armor, withIntegrityCheck);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="publicKeyStreams"></param>
        /// <param name="privateKeyStream"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyStream");
            if (passPhrase == null)
                passPhrase = String.Empty;

            foreach (Stream publicKey in publicKeyStreams)
            {
                if (publicKey == null)
                    throw new ArgumentException("PublicKeyStream");
            }

            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKeyStreams, privateKeyStream, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    OutputEncrypted(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, "name");
                }
            }
            else
                OutputEncrypted(inputStream, outputStream, encryptionKeys, withIntegrityCheck, "name");
        }

        private void OutputEncrypted(string inputFilePath, Stream outputStream, EncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys, withIntegrityCheck))
            {
                FileInfo unencryptedFileInfo = new FileInfo(inputFilePath);
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                    {
                        using (FileStream inputFileStream = unencryptedFileInfo.OpenRead())
                        {
                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                            inputFileStream.Dispose();
                        }
                    }
                }
            }
        }

        private void OutputSigned(string inputFilePath, Stream outputStream, EncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            FileInfo unencryptedFileInfo = new FileInfo(inputFilePath);
            using (Stream compressedOut = ChainCompressedOut(outputStream))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
                using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                {
                    using (FileStream inputFileStream = unencryptedFileInfo.OpenRead())
                    {
                        WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                        inputFileStream.Dispose();
                    }
                }
            }
        }

        private void OutputEncrypted(Stream inputStream, Stream outputStream, EncryptionKeys encryptionKeys, bool withIntegrityCheck, string name)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
                    using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
                    {
                        WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
                        inputStream.Dispose();
                    }
                }
            }
        }

        private void OutputSigned(Stream inputStream, Stream outputStream, EncryptionKeys encryptionKeys, bool withIntegrityCheck, string name)
        {
            using (Stream compressedOut = ChainCompressedOut(outputStream))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
                using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
                {
                    WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
                    inputStream.Dispose();
                }
            }
        }

        private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = inputFilePath.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            signatureGenerator.Generate().Encode(compressedOut);
        }

        private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, Stream inputStream, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            signatureGenerator.Generate().Encode(compressedOut);
        }

        private Stream ChainEncryptedOut(Stream outputStream, EncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            if (encryptionKeys.PublicKey != null)
            {
                encryptedDataGenerator.AddMethod(encryptionKeys.PublicKey);
            }
            else if (encryptionKeys.PublicKeys != null)
            {
                foreach (PgpPublicKey publicKey in encryptionKeys.PublicKeys)
                {
                    encryptedDataGenerator.AddMethod(publicKey);
                }
            }
            
            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private Stream ChainCompressedOut(Stream encryptedOut)
        {
            if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
            {
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                return compressedDataGenerator.Open(encryptedOut);
            }
            else
                return encryptedOut;
        }

        private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file.Name, file.Length, DateTime.Now);
        }

        private Stream ChainLiteralStreamOut(Stream compressedOut, Stream inputStream, string name)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length, DateTime.Now);
        }

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, EncryptionKeys encryptionKeys)
        {
            PublicKeyAlgorithmTag tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, encryptionKeys.PrivateKey);
            foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
            return pgpSignatureGenerator;
        }

        #endregion Encrypt and Sign

        #region Sign

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void SignFile(string inputFilePath, string outputFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                passPhrase = String.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFilePath));

            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKeyFilePath, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputSigned(inputFilePath, armoredOutputStream, encryptionKeys, withIntegrityCheck);
                    }
                }
                else
                    OutputSigned(inputFilePath, outputStream, encryptionKeys, withIntegrityCheck);
            }
        }

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="publicKeyStreams"></param>
        /// <param name="privateKeyStream"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void SignStream(Stream inputStream, Stream outputStream,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyStream");
            if (passPhrase == null)
                passPhrase = String.Empty;

            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    OutputSigned(inputStream, armoredOutputStream, encryptionKeys, withIntegrityCheck, "name");
                }
            }
            else
                OutputSigned(inputStream, outputStream, encryptionKeys, withIntegrityCheck, "name");
        }

        #endregion Sign

        #region Decrypt

        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, privateKeyFilePath, passPhrase));
        }

        public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            await Task.Run(() => DecryptStream(inputStream, outputStream, privateKeyStream, passPhrase));
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        public void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                passPhrase = String.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                using (Stream keyStream = File.OpenRead(privateKeyFilePath))
                {
                    using (Stream outStream = File.Create(outputFilePath))
                        Decrypt(inputStream, outStream, keyStream, passPhrase);
                }
            }
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        public Stream DecryptStream(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                passPhrase = String.Empty;

            Decrypt(inputStream, outputStream, privateKeyStream, passPhrase);
            return outputStream;
        }

        /*
        * PGP decrypt a given stream.
        */
        private void Decrypt(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("outputStream");
            if (privateKeyStream == null)
                throw new ArgumentException("privateKeyStream");
            if (passPhrase == null)
                passPhrase = String.Empty;

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact = null;

            using (Stream clear = pbe.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpOnePassSignatureList)
            {
                message = plainFact.NextPgpObject();
            }

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }

                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, outputStream);

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        throw new PgpException("Message failed integrity check.");
                    }
                }
            }
            else if (message is PgpOnePassSignatureList)
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            else
                throw new PgpException("Message is not a simple encrypted file.");
        }

        #endregion Decrypt

        #region DecryptAndVerify

        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            await Task.Run(() => DecryptFileAndVerify(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase));
        }

        public async Task DecryptStreamAndAndVerifyAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
        {
            await Task.Run(() => DecryptStreamAndVerify(inputStream, outputStream, publicKeyStream, privateKeyStream, passPhrase));
        }

        public async Task VerifyFileAsync(string inputFilePath, string publicKeyFilePath)
        {
            await Task.Run(() => VerifyFile(inputFilePath, publicKeyFilePath));
        }

        public async Task VerifyStreamAsync(Stream inputStream, Stream publicKeyStream)
        {
            await Task.Run(() => VerifyStream(inputStream, publicKeyStream));
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                passPhrase = String.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(String.Format("Public Key File [{0}] not found.", publicKeyFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyFilePath))
                using (Stream privateKeyStream = File.OpenRead(privateKeyFilePath))
                using (Stream outStream = File.Create(outputFilePath))
                    DecryptAndVerify(inputStream, outStream, publicKeyStream, privateKeyStream, passPhrase);
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        public Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (publicKeyStream == null)
                throw new ArgumentException("PublicKeyFileStream");
            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyFileStream");
            if (passPhrase == null)
                passPhrase = String.Empty;

            DecryptAndVerify(inputStream, outputStream, publicKeyStream, privateKeyStream, passPhrase);
            return outputStream;
        }

        /*
        * PGP decrypt and verify a given stream.
        */
        private void DecryptAndVerify(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);
            PgpPublicKeyEncryptedData publicKeyED = Utilities.ExtractPublicKeyEncryptedData(inputStream);

            if (publicKeyED.KeyId != encryptionKeys.PublicKey.KeyId)
                throw new PgpException(String.Format("Failed to verify file."));

            PgpObject message = Utilities.GetClearCompressedMessage(publicKeyED, encryptionKeys);

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact = null;

            using (Stream clear = pbe.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }

                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, outputStream);

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        throw new PgpException("Message failed integrity check.");
                    }
                }
            }
            else
                throw new PgpException("Message is not a simple encrypted file.");
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        public bool VerifyFile(string inputFilePath, string publicKeyFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(String.Format("Public Key File [{0}] not found.", publicKeyFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream publicKeyStream = File.OpenRead(publicKeyFilePath))
                return Verify(inputStream, publicKeyStream);
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="publicKeyStream"></param>
        public bool VerifyStream(Stream inputStream, Stream publicKeyStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (publicKeyStream == null)
                throw new ArgumentException("PublicKeyStream");

            return Verify(inputStream, publicKeyStream);
        }

        private bool Verify(Stream inputStream, Stream publicKeyStream)
        {
            PgpPublicKey publicKey = Utilities.ReadPublicKey(publicKeyStream);
            bool verified = false;

            System.IO.Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            if (pgpObject is PgpCompressedData)
            {
                PgpPublicKeyEncryptedData publicKeyED = Utilities.ExtractPublicKeyEncryptedData(encodedFile);

                if (publicKeyED.KeyId == publicKey.KeyId)
                {
                    verified = true;
                }
                else
                {
                    verified = false;
                }
            }
            else if (pgpObject is PgpEncryptedDataList)
            {
                PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)pgpObject;
                PgpPublicKeyEncryptedData publicKeyED = Utilities.ExtractPublicKey(encryptedDataList);

                if (publicKeyED.KeyId == publicKey.KeyId)
                {
                    verified = true;
                }
                else
                {
                    verified = false;
                }
            }
            else if (pgpObject is PgpOnePassSignatureList)
            {
                PgpOnePassSignatureList pgpOnePassSignatureList = (PgpOnePassSignatureList)pgpObject;
                PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

                if (pgpOnePassSignature.KeyId == publicKey.KeyId)
                {
                    verified = true;
                }
                else
                {
                    verified = false;
                }
            }
            else
                throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

            return verified;
        }

        #endregion DecryptAndVerify

        #region GenerateKey

        public async Task GenerateKeyAsync(string publicKeyFilePath, string privateKeyFilePath, string username = null, string password = null, int strength = 1024, int certainty = 8)
        {
            await Task.Run(() => GenerateKey(publicKeyFilePath, privateKeyFilePath, username, password, strength, certainty));
        }

        public void GenerateKey(string publicKeyFilePath, string privateKeyFilePath, string username = null, string password = null, int strength = 1024, int certainty = 8)
        {
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");

            using (Stream pubs = File.Open(publicKeyFilePath, FileMode.OpenOrCreate))
            using (Stream pris = File.Open(privateKeyFilePath, FileMode.OpenOrCreate))
                GenerateKey(pubs, pris, username, password, strength, certainty);
        }

        public void GenerateKey(Stream publicKeyStream, Stream privateKeyStream, string username = null, string password = null, int strength = 1024, int certainty = 8, bool armor = true)
        {
            username = username == null ? string.Empty : username;
            password = password == null ? string.Empty : password;

            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            ExportKeyPair(privateKeyStream, publicKeyStream, kp.Public, kp.Private, username, password.ToCharArray(), armor);
        }

        #endregion GenerateKey

        #region Private helpers

        private char FileTypeToChar()
        {
            if (FileType == PGPFileType.UTF8)
                return PgpLiteralData.Utf8;
            else if (FileType == PGPFileType.Text)
                return PgpLiteralData.Text;
            else
                return PgpLiteralData.Binary;

        }

        private void ExportKeyPair(
                    Stream secretOut,
                    Stream publicOut,
                    AsymmetricKeyParameter publicKey,
                    AsymmetricKeyParameter privateKey,
                    string identity,
                    char[] passPhrase,
                    bool armor)
        {
            if (secretOut == null)
                throw new ArgumentException("secretOut");
            if (publicOut == null)
                throw new ArgumentException("publicOut");

            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignatureType,
                PublicKeyAlgorithm,
                publicKey,
                privateKey,
                DateTime.Now,
                identity,
                SymmetricKeyAlgorithm,
                passPhrase,
                null,
                null,
                new SecureRandom()
                //                ,"BC"
                );

                secretKey.Encode(secretOut);

            secretOut.Dispose();

            if (armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOut.Dispose();
        }
        
        /*
        * Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        */
        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public void Dispose()
        {
        }

        #endregion Private helpers
    }
}
