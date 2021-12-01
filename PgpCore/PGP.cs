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
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public enum PGPFileType { Binary, Text, UTF8 }

    public class PGP : IPGPEncrypt, IPGPEncryptAsync, IPGPSign, IPGPSignAsync, IDisposable
    {
        public static readonly PGP Instance = new PGP();

        private const int BufferSize = 0x10000;
        private const string DefaultFileName = "name";

        public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Uncompressed;

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.TripleDes;

        public int PgpSignatureType { get; set; } = PgpSignature.DefaultCertification;

        public PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; } = PublicKeyAlgorithmTag.RsaGeneral;

        public PGPFileType FileType { get; set; } = PGPFileType.Binary;

        public HashAlgorithmTag HashAlgorithmTag { get; set; } = HashAlgorithmTag.Sha1;

        public IEncryptionKeys EncryptionKeys { get; private set; }

        #region Constructor

        public PGP() { }

        public PGP(IEncryptionKeys encryptionKeys) { EncryptionKeys = encryptionKeys; }

        #endregion Constructor

        #region Encrypt
        #region EncryptFileAsync

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            string publicKeyFilePath,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath));
            await EncryptFileAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="publicKeyFilePaths">PGP public key file paths</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            IEnumerable<string> publicKeyFilePaths,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFilePaths.Select(x => new FileInfo(x)).ToList());
            await EncryptFileAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            IEncryptionKeys encryptionKeys,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await EncryptFileAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputStream = File.Create(outputFilePath))
                await EncryptStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            FileInfo publicKeyFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile);
            await EncryptFileAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="publicKeyFiles">PGP public key files</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            IEnumerable<FileInfo> publicKeyFiles,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFiles);
            await EncryptFileAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            IEncryptionKeys encryptionKeys,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await EncryptFileAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.FullName));

            using (FileStream inputStream = inputFile.OpenRead())
            using (Stream outputStream = outputFile.OpenWrite())
                await EncryptStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        #endregion EncryptFileAsync
        #region EncryptFile

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            string inputFilePath,
            string outputFilePath,
            string publicKeyFilePath,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath));
            EncryptFile(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="publicKeyFilePaths">IEnumerable of PGP public key file paths</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            string inputFilePath,
            string outputFilePath,
            IEnumerable<string> publicKeyFilePaths,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFilePaths.Select(x => new FileInfo(x)).ToList());
            EncryptFile(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            string inputFilePath,
            string outputFilePath,
            IEncryptionKeys encryptionKeys,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            EncryptFile(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted</param>
        /// <param name="outputFilePath">Output PGP encrypted file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            string inputFilePath,
            string outputFilePath,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            using (FileStream inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (Stream outputStream = File.Create(outputFilePath))
                EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            FileInfo inputFile,
            FileInfo outputFile,
            FileInfo publicKeyFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile);
            EncryptFile(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="publicKeyFiles">PGP public key files</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            FileInfo inputFile,
            FileInfo outputFile,
            IEnumerable<FileInfo> publicKeyFiles,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFiles);
            EncryptFile(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            FileInfo inputFile,
            FileInfo outputFile,
            IEncryptionKeys encryptionKeys,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            EncryptFile(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFile(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.FullName));

            using (FileStream inputStream = inputFile.OpenRead())
            using (Stream outputStream = outputFile.OpenWrite())
                EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        #endregion EncryptFile
        #region EncryptStreamAsync

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAsync(
            Stream inputStream,
            Stream outputStream,
            Stream publicKeyStream,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream);
            await EncryptStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="publicKeyStreams">IEnumerable of PGP public key streams</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStreams);
            await EncryptStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await EncryptStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream)
            {
                string inputFilePath = ((FileStream)inputStream).Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            foreach (PgpPublicKey publicKey in EncryptionKeys.PublicKeys)
            {
                pk.AddMethod(publicKey);
            }

            Stream @out = pk.Open(outputStream, new byte[1 << 16]);

            if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
            {
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithm);
                await Utilities.WriteStreamToLiteralDataAsync(comData.Open(@out), FileTypeToChar(), inputStream, name);
                comData.Close();
            }
            else
                await Utilities.WriteStreamToLiteralDataAsync(@out, FileTypeToChar(), inputStream, name);

            @out.Close();

            if (armor)
            {
                outputStream.Close();
            }
        }

        #endregion EncryptStreamAsync
        #region EncryptStream

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStream(
            Stream inputStream,
            Stream outputStream,
            Stream publicKeyStream,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream);
            EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="publicKeyStreams">IEnumerable of PGP public key streams</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStream(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStreams);
            EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStream(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream)
            {
                string inputFilePath = ((FileStream)inputStream).Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            foreach (PgpPublicKey publicKey in EncryptionKeys.PublicKeys)
            {
                pk.AddMethod(publicKey);
            }

            Stream @out = pk.Open(outputStream, new byte[1 << 16]);

            if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
            {
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithm);
                Utilities.WriteStreamToLiteralData(comData.Open(@out), FileTypeToChar(), inputStream, name);
                comData.Close();
            }
            else
                Utilities.WriteStreamToLiteralData(@out, FileTypeToChar(), inputStream, name);

            @out.Close();

            if (armor)
            {
                outputStream.Close();
            }
        }

        #endregion EncryptStream
        #region EncryptArmoredStringAsync
        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAsync(
            string input,
            string publicKey,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(await publicKey.GetStreamAsync());

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="publicKeys">IEnumerable of PGP public keys</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAsync(string input, IEnumerable<string> publicKeys, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(await Task.WhenAll(publicKeys.Select(x => x.GetStreamAsync()).ToList()));

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAsync(string input, IEncryptionKeys encryptionKeys, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAsync(string input, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }
        #endregion EncryptArmoredStringAsync
        #region EncryptArmoredString
        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredString(
            string input,
            string publicKey,
            bool withIntegrityCheck = true,
            string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKey.GetStream());

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="publicKeys">IEnumerable of PGP public keys</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredString(string input, IEnumerable<string> publicKeys, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeys.Select(x => x.GetStream()).ToList());

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredString(string input, IEncryptionKeys encryptionKeys, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredString(string input, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }
        #endregion EncryptArmoredString
        #endregion Encrypt

        #region Encrypt and Sign
        #region EncryptFileAndSignAsync

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath), new FileInfo(privateKeyFilePath), passPhrase);
            await EncryptFileAndSignAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="publicKeyFilePaths">IEnumerable of PGP public key file paths</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, IEnumerable<string> publicKeyFilePaths,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFilePaths.Select(x => new FileInfo(x)).ToList(), new FileInfo(privateKeyFilePath), passPhrase);
            await EncryptFileAndSignAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await EncryptFileAndSignAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            if (name == DefaultFileName)
            {
                name = Path.GetFileName(inputFilePath);
            }

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        await OutputEncryptedAsync(inputFilePath, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    await OutputEncryptedAsync(inputFilePath, outputStream, withIntegrityCheck, name);
            }
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, FileInfo publicKeyFile,
            FileInfo privateKeyFile, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile, privateKeyFile, passPhrase);
            await EncryptFileAndSignAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="publicKeyFiles">IEnumerable of PGP public key files</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, IEnumerable<FileInfo> publicKeyFiles,
            FileInfo privateKeyFile, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFiles, privateKeyFile, passPhrase);
            await EncryptFileAndSignAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await EncryptFileAndSignAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFilePath");
            if (outputFile == null)
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.FullName));

            if (name == DefaultFileName)
            {
                name = inputFile.Name;
            }

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        await OutputEncryptedAsync(inputFile, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    await OutputEncryptedAsync(inputFile, outputStream, withIntegrityCheck, name);
            }
        }

        #endregion EncryptFileAndSignAsync
        #region EncryptFileAndSign

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath), new FileInfo(privateKeyFilePath), passPhrase);
            EncryptFileAndSign(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="publicKeyFilePaths">IEnumerable of PGP public key file paths</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, IEnumerable<string> publicKeyFilePaths,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFilePaths.Select(x => new FileInfo(x)).ToList(), new FileInfo(privateKeyFilePath), passPhrase);
            EncryptFileAndSign(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            EncryptFileAndSign(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            if (name == DefaultFileName)
            {
                name = Path.GetFileName(inputFilePath);
            }

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(inputFilePath, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    OutputEncrypted(inputFilePath, outputStream, withIntegrityCheck, name);
            }
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, FileInfo publicKeyFile,
            FileInfo privateKeyFile, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile, privateKeyFile, passPhrase);
            EncryptFileAndSign(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="publicKeyFiles">IEnumerable of PGP public key files</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, IEnumerable<FileInfo> publicKeyFiles,
            FileInfo privateKeyFile, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFiles, privateKeyFile, passPhrase);
            EncryptFileAndSign(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            EncryptFileAndSign(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFilePath">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFilePath");
            if (outputFile == null)
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.FullName));

            if (name == DefaultFileName)
            {
                name = inputFile.Name;
            }

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(inputFile, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    OutputEncrypted(inputFile, outputStream, withIntegrityCheck, name);
            }
        }

        #endregion EncryptFileAndSign
        #region EncryptStreamAndSignAsync

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);
            await EncryptStreamAndSignAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="publicKeyStreams">IEnumerable of PGP public key streams</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStreams, privateKeyStream, passPhrase);
            await EncryptStreamAndSignAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await EncryptStreamAndSignAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream)
            {
                string inputFilePath = ((FileStream)inputStream).Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    await OutputEncryptedAsync(inputStream, armoredOutputStream, withIntegrityCheck, name);
                }
            }
            else
                await OutputEncryptedAsync(inputStream, outputStream, withIntegrityCheck, name);
        }

        #endregion EncryptStreamAndSignAsync
        #region EncryptStreamAndSign

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, Stream publicKeyStream,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);
            EncryptStreamAndSign(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="publicKeyStreams">IEnumerable of PGP public key streams</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, IEnumerable<Stream> publicKeyStreams,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStreams, privateKeyStream, passPhrase);
            EncryptStreamAndSign(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            EncryptStreamAndSign(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream)
            {
                string inputFilePath = ((FileStream)inputStream).Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    OutputEncrypted(inputStream, armoredOutputStream, withIntegrityCheck, name);
                }
            }
            else
                OutputEncrypted(inputStream, outputStream, withIntegrityCheck, name);
        }

        #endregion EncryptStreamAndSign
        #region EncryptArmoredStringAndSignAsync
        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAndSignAsync(string input, string publicKey,
            string privateKey, string passPhrase, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(await publicKey.GetStreamAsync(), await privateKey.GetStreamAsync(), passPhrase);

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAndSignAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="publicKeys">IEnumerable of PGP public keys</param>
        /// <param name="privateKey">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAndSignAsync(string input, List<string> publicKeys,
            string privateKey, string passPhrase, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(await Task.WhenAll(publicKeys.Select(x => x.GetStreamAsync()).ToList()), await privateKey.GetStreamAsync(), passPhrase);

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAndSignAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAndSignAsync(string input, IEncryptionKeys encryptionKeys, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAndSignAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public async Task<string> EncryptArmoredStringAndSignAsync(string input, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAndSignAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }
        #endregion EncryptArmoredStringAndSignAsync
        #region EncryptArmoredStringAndSign
        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredStringAndSign(string input, string publicKey,
            string privateKey, string passPhrase, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKey.GetStream(), privateKey.GetStream(), passPhrase);

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStreamAndSign(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="publicKeys">IEnumerable of PGP public keys</param>
        /// <param name="privateKey">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredStringAndSign(string input, List<string> publicKeys,
            string privateKey, string passPhrase, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(publicKeys.Select(x => x.GetStream()).ToList(), privateKey.GetStream(), passPhrase);

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStreamAndSign(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        public string EncryptArmoredStringAndSign(string input, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStreamAndSign(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }
        #endregion EncryptArmoredStringAndSign
        #endregion Encrypt and Sign

        #region Sign
        #region SignFileAsync
        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignFileAsync(string inputFilePath, string outputFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(privateKeyFilePath), passPhrase);
            await SignFileAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignFileAsync(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await SignFileAsync(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignFileAsync(string inputFilePath, string outputFilePath,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            if (name == DefaultFileName)
            {
                name = Path.GetFileName(inputFilePath);
            }

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        await OutputSignedAsync(inputFilePath, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    await OutputSignedAsync(inputFilePath, outputStream, withIntegrityCheck, name);
            }
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignFileAsync(FileInfo inputFile, FileInfo outputFile,
            FileInfo privateKeyFile, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyFile, passPhrase);
            await SignFileAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignFileAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await SignFileAsync(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignFileAsync(FileInfo inputFile, FileInfo outputFile,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.FullName));

            if (name == DefaultFileName)
            {
                name = inputFile.Name;
            }

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        await OutputSignedAsync(inputFile, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    await OutputSignedAsync(inputFile, outputStream, withIntegrityCheck, name);
            }
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignFile(FileInfo inputFile, FileInfo outputFile,
            FileInfo privateKeyFile, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyFile, passPhrase);
            SignFile(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignFile(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            SignFile(inputFile, outputFile, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignFile(FileInfo inputFile, FileInfo outputFile,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.FullName));

            if (name == DefaultFileName)
            {
                name = inputFile.Name;
            }

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputSigned(inputFile, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    OutputSigned(inputFile, outputStream, withIntegrityCheck, name);
            }
        }

        #endregion SignFileAsync
        #region SignFile

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignFile(string inputFilePath, string outputFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(privateKeyFilePath), passPhrase);
            SignFile(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignFile(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            SignFile(inputFilePath, outputFilePath, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignFile(string inputFilePath, string outputFilePath,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            if (name == DefaultFileName)
            {
                name = Path.GetFileName(inputFilePath);
            }

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputSigned(inputFilePath, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    OutputSigned(inputFilePath, outputStream, withIntegrityCheck, name);
            }
        }

        #endregion SignFile
        #region SignStreamAsync

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignStreamAsync(Stream inputStream, Stream outputStream,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
            await SignStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            await SignStreamAsync(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignStreamAsync(Stream inputStream, Stream outputStream,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream)
            {
                string inputFilePath = ((FileStream)inputStream).Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    await OutputSignedAsync(inputStream, armoredOutputStream, withIntegrityCheck, name);
                }
            }
            else
                await OutputSignedAsync(inputStream, outputStream, withIntegrityCheck, name);
        }

        #endregion SignStreamAsync
        #region SignStream

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignStream(Stream inputStream, Stream outputStream,
            Stream privateKeyStream, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
            SignStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;
            SignStream(inputStream, outputStream, armor, withIntegrityCheck, name);
        }

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public void SignStream(Stream inputStream, Stream outputStream,
            bool armor = true, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream)
            {
                string inputFilePath = ((FileStream)inputStream).Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    OutputSigned(inputStream, armoredOutputStream, withIntegrityCheck, name);
                }
            }
            else
                OutputSigned(inputStream, outputStream, withIntegrityCheck, name);
        }

        #endregion SignStream
        #region SignArmoredStringAsync
        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task<string> SignArmoredStringAsync(string input, string privateKey, string passPhrase, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(await privateKey.GetStreamAsync(), passPhrase);

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await SignStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task<string> SignArmoredStringAsync(string input, IEncryptionKeys encryptionKeys,
            bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await SignStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task<string> SignArmoredStringAsync(string input, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await SignStreamAsync(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }
        #endregion SignArmoredStringAsync
        #region SignArmoredString
        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public string SignArmoredString(string input, string privateKey, string passPhrase, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = new EncryptionKeys(privateKey.GetStream(), passPhrase);

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                SignStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public string SignArmoredString(string input, IEncryptionKeys encryptionKeys,
            bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                SignStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public string SignArmoredString(string input, bool withIntegrityCheck = true, string name = DefaultFileName)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                SignStream(inputStream, outputStream, true, withIntegrityCheck, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }
        #endregion SignArmoredString
        #endregion Sign

        #region ClearSign
        #region ClearSignFileAsync

        // https://github.com/bcgit/bc-csharp/blob/f18a2dbbc2c1b4277e24a2e51f09cac02eedf1f5/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task ClearSignFileAsync(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(privateKeyFilePath), passPhrase);
            await ClearSignFileAsync(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task ClearSignFileAsync(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await ClearSignFileAsync(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        public async Task ClearSignFileAsync(string inputFilePath, string outputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            using (Stream outputStream = File.Create(outputFilePath))
            {
                await OutputClearSignedAsync(inputFilePath, outputStream);
            }
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile, FileInfo privateKeyFile, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyFile, passPhrase);
            await ClearSignFileAsync(inputFile, outputFile);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await ClearSignFileAsync(inputFile, outputFile);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        public async Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.Name));

            using (Stream outputStream = outputFile.OpenWrite())
            {
                await OutputClearSignedAsync(inputFile, outputStream);
            }
        }

        #endregion ClearSignFileAsync
        #region ClearSignFile

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void ClearSignFile(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(privateKeyFilePath), passPhrase);
            ClearSignFile(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void ClearSignFile(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            ClearSignFile(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be signed</param>
        /// <param name="outputFilePath">Output PGP signed file path</param>
        public void ClearSignFile(string inputFilePath, string outputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

            using (Stream outputStream = File.Create(outputFilePath))
            {
                OutputClearSigned(inputFilePath, outputStream);
            }
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void ClearSignFile(FileInfo inputFile, FileInfo outputFile, FileInfo privateKeyFile, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyFile, passPhrase);
            ClearSignFile(inputFile, outputFile);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void ClearSignFile(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            ClearSignFile(inputFile, outputFile);
        }

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        public void ClearSignFile(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFile.Name));

            using (Stream outputStream = outputFile.OpenWrite())
            {
                OutputClearSigned(inputFile, outputStream);
            }
        }

        #endregion ClearSignFile
        #region ClearSignStreamAsync

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task ClearSignStreamAsync(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
            await ClearSignStreamAsync(inputStream, outputStream);
        }

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task ClearSignStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await ClearSignStreamAsync(inputStream, outputStream);
        }

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task ClearSignStreamAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            await OutputClearSignedAsync(inputStream, outputStream);
        }

        #endregion ClearSignStreamAsync
        #region ClearSignStream

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void ClearSignStream(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
            ClearSignStream(inputStream, outputStream);
        }

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void ClearSignStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            ClearSignStream(inputStream, outputStream);
        }

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        public void ClearSignStream(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            OutputClearSigned(inputStream, outputStream);
        }

        #endregion ClearSignStream
        #region ClearSignArmoredStringAsync
        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task<string> ClearSignArmoredStringAsync(string input, string privateKey, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(await privateKey.GetStreamAsync(), passPhrase);

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await ClearSignStreamAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<string> ClearSignArmoredStringAsync(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await ClearSignStreamAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        public async Task<string> ClearSignArmoredStringAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await ClearSignStreamAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }
        #endregion ClearSignArmoredStringAsync
        #region ClearSignArmoredString
        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public string ClearSignArmoredString(string input, string privateKey, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKey.GetStream(), passPhrase);

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                ClearSignStream(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public string ClearSignArmoredString(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                ClearSignStream(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        public string ClearSignArmoredString(string input)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                ClearSignStream(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }
        #endregion ClearSignArmoredString
        #endregion ClearSign

        #region Decrypt
        #region DecryptFileAsync

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <param name="outputFilePath">Output PGP decrypted file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(privateKeyFilePath), passPhrase);
            await DecryptFileAsync(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <param name="outputFilePath">Output PGP decrypted file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await DecryptFileAsync(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <param name="outputFilePath">Output PGP decrypted file path</param>
        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outStream = File.Create(outputFilePath))
                await DecryptStreamAsync(inputStream, outStream);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile, FileInfo privateKeyFile, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyFile, passPhrase);
            await DecryptFileAsync(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await DecryptFileAsync(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        public async Task DecryptFileAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFile.FullName));

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptStreamAsync(inputStream, outStream);
        }

        #endregion DecryptFileAsync
        #region DecryptFile

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <param name="outputFilePath">Output PGP decrypted file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(privateKeyFilePath), passPhrase);
            DecryptFile(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <param name="outputFilePath">Output PGP decrypted file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void DecryptFile(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            DecryptFile(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <param name="outputFilePath">Output PGP decrypted file path</param>
        public void DecryptFile(string inputFilePath, string outputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outStream = File.Create(outputFilePath))
                Decrypt(inputStream, outStream);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void DecryptFile(FileInfo inputFile, FileInfo outputFile, FileInfo privateKeyFile, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyFile, passPhrase);
            DecryptFile(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void DecryptFile(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            DecryptFile(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        public void DecryptFile(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFile.FullName));

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                DecryptStream(inputStream, outStream);
        }

        #endregion DecryptFile
        #region DecryptStreamAsync

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task<Stream> DecryptStreamAsync(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
            await DecryptStreamAsync(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<Stream> DecryptStreamAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await DecryptStreamAsync(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        public async Task<Stream> DecryptStreamAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            await DecryptAsync(inputStream, outputStream);
            return outputStream;
        }

        #endregion DecryptStreamAsync
        #region DecryptStream

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public Stream DecryptStream(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKeyStream, passPhrase);
            DecryptStream(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public Stream DecryptStream(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            DecryptStream(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        public Stream DecryptStream(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            Decrypt(inputStream, outputStream);
            return outputStream;
        }

        #endregion DecryptStream
        #region DecryptArmoredStringAsync
        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted data stream</param>
        /// <param name="privateKey">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task<string> DecryptArmoredStringAsync(string input, string privateKey, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(await privateKey.GetStreamAsync(), passPhrase);

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptStreamAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<string> DecryptArmoredStringAsync(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptStreamAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        public async Task<string> DecryptArmoredStringAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptStreamAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }
        #endregion DecryptArmoredStringAsync
        #region DecryptArmoredString
        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="input">PGP encrypted data stream</param>
        /// <param name="privateKey">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public string DecryptArmoredString(string input, string privateKey, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(privateKey.GetStream(), passPhrase);

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                DecryptStream(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public string DecryptArmoredString(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                DecryptStream(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        public string DecryptArmoredString(string input)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                DecryptStream(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }
        #endregion DecryptArmoredString
        #endregion Decrypt

        #region DecryptAndVerify
        #region DecryptFileAndVerifyAsync

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath), new FileInfo(privateKeyFilePath), passPhrase);
            await DecryptFileAndVerifyAsync(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await DecryptFileAndVerifyAsync(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outStream = File.Create(outputFilePath))
                await DecryptStreamAndVerifyAsync(inputStream, outStream);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile, FileInfo publicKeyFile, FileInfo privateKeyFile, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile, privateKeyFile, passPhrase);
            await DecryptFileAndVerifyAsync(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await DecryptFileAndVerifyAsync(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        public async Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFile.FullName));

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptStreamAndVerifyAsync(inputStream, outStream);
        }

        #endregion DecryptFileAndVerifyAsync
        #region DecryptFileAndVerify

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        /// <param name="privateKeyFilePath">PGP secret key file path</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath), new FileInfo(privateKeyFilePath), passPhrase);
            DecryptFileAndVerify(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            DecryptFileAndVerify(inputFilePath, outputFilePath);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (String.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outStream = File.Create(outputFilePath))
                DecryptAndVerify(inputStream, outStream);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        /// <param name="privateKeyFile">PGP secret key file</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile, FileInfo publicKeyFile, FileInfo privateKeyFile, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile, privateKeyFile, passPhrase);
            DecryptFileAndVerify(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            DecryptFileAndVerify(inputFile, outputFile);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFilePath">Output PGP decrypted and verified file path</param>
        public void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFile.FullName));

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                DecryptStreamAndVerify(inputStream, outStream);
        }

        #endregion DecryptFileAndVerify
        #region DecryptStreamAndVerifyAsync

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);
            await DecryptStreamAndVerifyAsync(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public key, private key and passphrase</param>
        public async Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            await DecryptStreamAndVerifyAsync(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public async Task<Stream> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            await DecryptAndVerifyAsync(inputStream, outputStream);
            return outputStream;
        }

        #endregion DecryptStreamAndVerifyAsync
        #region DecryptStreamAndVerify

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        /// <param name="privateKeyStream">PGP secret key stream</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream, Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, passPhrase);
            DecryptStreamAndVerify(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            DecryptStreamAndVerify(inputStream, outputStream);
            return outputStream;
        }

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public Stream DecryptStreamAndVerify(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            DecryptAndVerify(inputStream, outputStream);
            return outputStream;
        }

        #endregion DecryptStreamAndVerify
        #region DecryptArmoredStringAndVerifyAsync
        /// <summary>
        /// PGP decrypt and verify a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public async Task<string> DecryptArmoredStringAndVerifyAsync(string input, string publicKey, string privateKey, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(await publicKey.GetStreamAsync(), await privateKey.GetStreamAsync(), passPhrase);

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptStreamAndVerifyAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public key, private key and passphrase</param>
        public async Task<string> DecryptArmoredStringAndVerifyAsync(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptStreamAndVerifyAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        public async Task<string> DecryptArmoredStringAndVerifyAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await DecryptStreamAndVerifyAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }
        #endregion DecryptArmoredStringAndVerifyAsync
        #region DecryptArmoredStringAndVerify
        /// <summary>
        /// PGP decrypt and verify a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="privateKey">PGP secret key</param>
        /// <param name="passPhrase">PGP secret key password</param>
        public string DecryptArmoredStringAndVerify(string input, string publicKey, string privateKey, string passPhrase)
        {
            EncryptionKeys = new EncryptionKeys(publicKey.GetStream(), privateKey.GetStream(), passPhrase);

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                DecryptStreamAndVerify(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public key, private key and passphrase</param>
        public string DecryptArmoredStringAndVerify(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                DecryptStreamAndVerify(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        public string DecryptArmoredStringAndVerify(string input)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                DecryptStreamAndVerify(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }
        #endregion DecryptArmoredStringAndVerify
        #region VerifyFileAsync

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        public async Task<bool> VerifyFileAsync(string inputFilePath, string publicKeyFilePath)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath));
            return await VerifyFileAsync(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        public async Task<bool> VerifyFileAsync(string inputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return await VerifyFileAsync(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        public async Task<bool> VerifyFileAsync(string inputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
                return await VerifyAsync(inputStream);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        public async Task<bool> VerifyFileAsync(FileInfo inputFile, FileInfo publicKeyFile)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile);
            return await VerifyFileAsync(inputFile);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        public async Task<bool> VerifyFileAsync(FileInfo inputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return await VerifyFileAsync(inputFile);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        public async Task<bool> VerifyFileAsync(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFile.FullName));

            using (Stream inputStream = inputFile.OpenRead())
                return await VerifyAsync(inputStream);
        }

        #endregion VerifyFileAsync
        #region VerifyFile

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        public bool VerifyFile(string inputFilePath, string publicKeyFilePath)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath));
            return VerifyFile(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyFile(string inputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return VerifyFile(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        public bool VerifyFile(string inputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
                return Verify(inputStream);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        public bool VerifyFile(FileInfo inputFile, FileInfo publicKeyFile)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile);
            return VerifyFile(inputFile);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="encryptionKeys">IEncryptionKeys object containing public keys</param>
        public bool VerifyFile(FileInfo inputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return VerifyFile(inputFile);
        }

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        public bool VerifyFile(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFile.FullName));

            using (Stream inputStream = inputFile.OpenRead())
                return Verify(inputStream);
        }

        #endregion VerifyFile
        #region VerifyStreamAsync

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        public async Task<bool> VerifyStreamAsync(Stream inputStream, Stream publicKeyStream)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream);
            return await VerifyStreamAsync(inputStream);
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<bool> VerifyStreamAsync(Stream inputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return await VerifyStreamAsync(inputStream);
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        public async Task<bool> VerifyStreamAsync(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return await VerifyAsync(inputStream);
        }

        #endregion VerifyStreamAsync
        #region VerifyStream

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        public bool VerifyStream(Stream inputStream, Stream publicKeyStream)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream);
            return Verify(inputStream);
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyStream(Stream inputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return Verify(inputStream);
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        public bool VerifyStream(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return Verify(inputStream);
        }

        #endregion VerifyStream
        #region VerifyArmoredStringAsync
        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="publicKey">PGP public key stream</param>
        public async Task<bool> VerifyArmoredStringAsync(string input, string publicKey)
        {
            EncryptionKeys = new EncryptionKeys(await publicKey.GetStreamAsync());

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                return await VerifyStreamAsync(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<bool> VerifyArmoredStringAsync(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                return await VerifyStreamAsync(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        public async Task<bool> VerifyArmoredStringAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                return await VerifyStreamAsync(inputStream);
            }
        }
        #endregion VerifyArmoredStringAsync
        #region VerifyArmoredString
        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="publicKey">PGP public key</param>
        public bool VerifyArmoredString(string input, string publicKey)
        {
            EncryptionKeys = new EncryptionKeys(publicKey.GetStream());

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                return VerifyStream(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyArmoredString(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                return VerifyStream(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        public bool VerifyArmoredString(string input)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                return VerifyStream(inputStream);
            }
        }
        #endregion VerifyArmoredString
        #region VerifyClearFileAsync

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        public async Task<bool> VerifyClearFileAsync(string inputFilePath, string publicKeyFilePath)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath));
            return await VerifyClearFileAsync(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<bool> VerifyClearFileAsync(string inputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return await VerifyClearFileAsync(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        public async Task<bool> VerifyClearFileAsync(string inputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");

            using (Stream inputStream = File.OpenRead(inputFilePath))
                return await VerifyClearAsync(inputStream);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        public async Task<bool> VerifyClearFileAsync(FileInfo inputFile, FileInfo publicKeyFile)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile);
            return await VerifyClearFileAsync(inputFile);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<bool> VerifyClearFileAsync(FileInfo inputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return await VerifyClearFileAsync(inputFile);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        public async Task<bool> VerifyClearFileAsync(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");

            using (Stream inputStream = inputFile.OpenRead())
                return await VerifyClearAsync(inputStream);
        }

        #endregion VerifyClearFileAsync
        #region VerifyClearFile

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="publicKeyFilePath">PGP public key file path</param>
        public bool VerifyClearFile(string inputFilePath, string publicKeyFilePath)
        {
            EncryptionKeys = new EncryptionKeys(new FileInfo(publicKeyFilePath));
            return VerifyClearFile(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyClearFile(string inputFilePath, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return VerifyClearFile(inputFilePath);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFilePath">Plain data file path to be verified</param>
        public bool VerifyClearFile(string inputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
                return VerifyClear(inputStream);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="publicKeyFile">PGP public key file</param>
        public bool VerifyClearFile(FileInfo inputFile, FileInfo publicKeyFile)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyFile);
            return VerifyClearFile(inputFile);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyClearFile(FileInfo inputFile, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return VerifyClearFile(inputFile);
        }

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        public bool VerifyClearFile(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");

            using (Stream inputStream = inputFile.OpenRead())
                return VerifyClear(inputStream);
        }

        #endregion VerifyClearFile
        #region VerifyClearStreamAsync

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        public async Task<bool> VerifyClearStreamAsync(Stream inputStream, Stream publicKeyStream)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream);
            return await VerifyClearStreamAsync(inputStream);
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<bool> VerifyClearStreamAsync(Stream inputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return await VerifyClearStreamAsync(inputStream);
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        public async Task<bool> VerifyClearStreamAsync(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return await VerifyClearAsync(inputStream);
        }

        #endregion VerifyClearStreamAsync
        #region VerifyClearStream

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed stream to be verified</param>
        /// <param name="publicKeyStream">PGP public key stream</param>
        public bool VerifyClearStream(Stream inputStream, Stream publicKeyStream)
        {
            EncryptionKeys = new EncryptionKeys(publicKeyStream);
            return VerifyClearStream(inputStream);
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed stream to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyClearStream(Stream inputStream, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
            return VerifyClearStream(inputStream);
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed stream to be verified</param>
        public bool VerifyClearStream(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return VerifyClear(inputStream);
        }

        #endregion VerifyClearStream
        #region VerifyClearArmoredStringAsync
        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        /// <param name="publicKey">PGP public key</param>
        public async Task<bool> VerifyClearArmoredStringAsync(string input, string publicKey)
        {
            EncryptionKeys = new EncryptionKeys(await publicKey.GetStreamAsync());

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                return await VerifyClearStreamAsync(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public async Task<bool> VerifyClearArmoredStringAsync(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                return await VerifyClearStreamAsync(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public async Task<bool> VerifyClearArmoredStringAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                return await VerifyClearStreamAsync(inputStream);
            }
        }
        #endregion VerifyClearArmoredStringAsync
        #region VerifyClearArmoredString
        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        /// <param name="publicKey">PGP public key</param>
        public bool VerifyClearArmoredString(string input, string publicKey)
        {
            EncryptionKeys = new EncryptionKeys(publicKey.GetStream());

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                return VerifyClearStream(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        /// <param name="encryptionKeys">Encryption keys</param>
        public bool VerifyClearArmoredString(string input, IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                return VerifyClearStream(inputStream);
            }
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public bool VerifyClearArmoredString(string input)
        {
            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                return VerifyClearStream(inputStream);
            }
        }
        #endregion VerifyClearArmoredString
        #endregion DecryptAndVerify

        #region GetRecipients

        /// <summary>
        /// PGP get a recipients keys id of an encrypted file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
        public IEnumerable<long> GetFileRecipients(string inputFilePath)
        {
            if (String.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
                return GetStreamRecipients(inputStream);
        }

        /// <summary>
        /// PGP get a recipients keys id of an encrypted stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
        public IEnumerable<long> GetStreamRecipients(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;

            if (obj is PgpEncryptedDataList list)
                enc = list;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc is null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            // Return keys id
            return enc.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().Select(k => k.KeyId);
        }

        /// <summary>
        /// PGP get a recipients keys id of an encrypted file.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        /// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
        public IEnumerable<long> GetArmoredStringRecipients(string input)
        {
            if (String.IsNullOrEmpty(input))
                throw new ArgumentException("Input");

            using (Stream inputStream = input.GetStream())
                return GetStreamRecipients(inputStream);
        }

        #endregion GetRecipients

        #region GenerateKey

        public async Task GenerateKeyAsync(string publicKeyFilePath, string privateKeyFilePath, string username = null, string password = null, int strength = 1024, int certainty = 8, bool emitVersion = true)
        {
            await Task.Run(() => GenerateKey(publicKeyFilePath, privateKeyFilePath, username, password, strength, certainty, emitVersion));
        }

        public void GenerateKey(string publicKeyFilePath, string privateKeyFilePath, string username = null, string password = null, int strength = 1024, int certainty = 8, bool emitVersion = true)
        {
            if (String.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (String.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");

            using (Stream pubs = File.Open(publicKeyFilePath, FileMode.Create))
            using (Stream pris = File.Open(privateKeyFilePath, FileMode.Create))
                GenerateKey(pubs, pris, username, password, strength, certainty, emitVersion: emitVersion);
        }

        public void GenerateKey(Stream publicKeyStream, Stream privateKeyStream, string username = null, string password = null, int strength = 1024, int certainty = 8, bool armor = true, bool emitVersion = true)
        {
            username = username == null ? string.Empty : username;
            password = password == null ? string.Empty : password;

            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            ExportKeyPair(privateKeyStream, publicKeyStream, kp.Public, kp.Private, username, password.ToCharArray(), armor, emitVersion);
        }

        #endregion GenerateKey

        #region Private helpers
        #region OutputEncryptedAsync

        private async Task OutputEncryptedAsync(string inputFilePath, Stream outputStream, bool withIntegrityCheck, string name)
        {
            await OutputEncryptedAsync(new FileInfo(inputFilePath), outputStream, withIntegrityCheck, name);
        }

        private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
                    {
                        using (FileStream inputFileStream = inputFile.OpenRead())
                        {
                            await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator);
                        }
                    }
                }
            }
        }

        private async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
                    {
                        await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
                    }
                }
            }
        }

        #endregion OutputEncryptedAsync
        #region OutputEncrypted

        private void OutputEncrypted(string inputFilePath, Stream outputStream, bool withIntegrityCheck, string name)
        {
            OutputEncrypted(new FileInfo(inputFilePath), outputStream, withIntegrityCheck, name);
        }

        private void OutputEncrypted(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
                    {
                        using (FileStream inputFileStream = inputFile.OpenRead())
                        {
                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                        }
                    }
                }
            }
        }

        private void OutputEncrypted(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
                    {
                        WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
                    }
                }
            }
        }

        #endregion OutputEncrypted
        #region OutputSignedAsync

        private async Task OutputSignedAsync(string inputFilePath, Stream outputStream, bool withIntegrityCheck, string name)
        {
            await OutputSignedAsync(new FileInfo(inputFilePath), outputStream, withIntegrityCheck, name);
        }

        private async Task OutputSignedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream compressedOut = ChainCompressedOut(outputStream))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
                {
                    using (FileStream inputFileStream = inputFile.OpenRead())
                    {
                        await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator);
                    }
                }
            }
        }

        private async Task OutputSignedAsync(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream compressedOut = ChainCompressedOut(outputStream))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
                {
                    await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
                }
            }
        }

        #endregion OutputSignedAsync
        #region OutputSigned

        private void OutputSigned(string inputFilePath, Stream outputStream, bool withIntegrityCheck, string name)
        {
            OutputSigned(new FileInfo(inputFilePath), outputStream, withIntegrityCheck, name);
        }

        private void OutputSigned(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream compressedOut = ChainCompressedOut(outputStream))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
                {
                    using (FileStream inputFileStream = inputFile.OpenRead())
                    {
                        WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                    }
                }
            }
        }

        private void OutputSigned(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name)
        {
            using (Stream compressedOut = ChainCompressedOut(outputStream))
            {
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
                {
                    WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
                }
            }
        }

        #endregion OutputSigned
        #region OutputClearSignedAsync

        private async Task OutputClearSignedAsync(string inputFilePath, Stream outputStream)
        {
            await OutputClearSignedAsync(new FileInfo(inputFilePath), outputStream);
        }

        private async Task OutputClearSignedAsync(FileInfo inputFile, Stream outputStream)
        {
            using (FileStream inputFileStream = inputFile.OpenRead())
            {
                await OutputClearSignedAsync(inputFileStream, outputStream);
            }
        }

        private async Task OutputClearSignedAsync(Stream inputStream, Stream outputStream)
        {
            using (StreamReader streamReader = new StreamReader(inputStream))
            using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
            {
                PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

                while (streamReader.Peek() >= 0)
                {
                    string line = await streamReader.ReadLineAsync();
                    byte[] lineByteArray = Encoding.ASCII.GetBytes(line);
                    // Does the line end with whitespace?
                    // Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
                    string cleanLine = line.TrimEnd();
                    byte[] cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

                    pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
                    await armoredOutputStream.WriteAsync(lineByteArray, 0, lineByteArray.Length);

                    // Add a line break back to the stream
                    armoredOutputStream.Write((byte)'\r');
                    armoredOutputStream.Write((byte)'\n');

                    // Update signature with line breaks unless we're on the last line
                    if (streamReader.Peek() >= 0)
                    {
                        pgpSignatureGenerator.Update((byte)'\r');
                        pgpSignatureGenerator.Update((byte)'\n');
                    }
                }

                armoredOutputStream.EndClearText();

                BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
                pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
            }
        }

        #endregion OutputClearSignedAsync
        #region OutputClearSigned

        private void OutputClearSigned(string inputFilePath, Stream outputStream)
        {
            OutputClearSigned(new FileInfo(inputFilePath), outputStream);
        }

        private void OutputClearSigned(FileInfo inputFile, Stream outputStream)
        {
            using (FileStream inputFileStream = inputFile.OpenRead())
            {
                OutputClearSigned(inputFileStream, outputStream);
            }
        }

        private void OutputClearSigned(Stream inputStream, Stream outputStream)
        {
            using (StreamReader streamReader = new StreamReader(inputStream))
            using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
            {
                PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

                while (streamReader.Peek() >= 0)
                {
                    string line = streamReader.ReadLine();
                    byte[] lineByteArray = Encoding.ASCII.GetBytes(line);
                    // Does the line end with whitespace?
                    // Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
                    string cleanLine = line.TrimEnd();
                    byte[] cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

                    pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
                    armoredOutputStream.Write(lineByteArray, 0, lineByteArray.Length);

                    // Add a line break back to the stream
                    armoredOutputStream.Write((byte)'\r');
                    armoredOutputStream.Write((byte)'\n');

                    // Update signature with line breaks unless we're on the last line
                    if (streamReader.Peek() >= 0)
                    {
                        pgpSignatureGenerator.Update((byte)'\r');
                        pgpSignatureGenerator.Update((byte)'\n');
                    }
                }

                armoredOutputStream.EndClearText();

                BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
                pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
            }
        }

        #endregion OutputClearSigned
        #region DecryptAsync

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <returns></returns>
        private async Task DecryptAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else if (obj is PgpCompressedData)
                message = (PgpCompressedData)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            if (enc != null)
            {
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    privateKey = EncryptionKeys.FindSecretKey(pked.KeyId);

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

                message = plainFact.NextPgpObject();

                if (message is PgpOnePassSignatureList)
                {
                    message = plainFact.NextPgpObject();
                }
            }

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                    message = of.NextPgpObject();
                }

                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    await Streams.PipeAllAsync(unc, outputStream);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    await Streams.PipeAllAsync(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                await Streams.PipeAllAsync(unc, outputStream);

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

        #endregion DecryptAsync
        #region Decrypt

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <returns></returns>
        private void Decrypt(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else if (obj is PgpCompressedData)
                message = (PgpCompressedData)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            if (enc != null)
            {
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    privateKey = EncryptionKeys.FindSecretKey(pked.KeyId);

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

                message = plainFact.NextPgpObject();

                if (message is PgpOnePassSignatureList)
                {
                    message = plainFact.NextPgpObject();
                }
            }

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                    message = of.NextPgpObject();
                }
                
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
        #region DecryptAndVerifyAsync

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        private async Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream)
        {
            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedDataList = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList)
                encryptedDataList = (PgpEncryptedDataList)obj;
            else if (obj is PgpCompressedData)
                message = (PgpCompressedData)obj;
            else
                encryptedDataList = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (encryptedDataList == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            if (encryptedDataList != null)
            {
                foreach (PgpPublicKeyEncryptedData pked in encryptedDataList.GetEncryptedDataObjects())
                {
                    privateKey = EncryptionKeys.FindSecretKey(pked.KeyId);

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

                message = plainFact.NextPgpObject();

                if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                {
                    PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

                    var verified = EncryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || EncryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
                    if (verified == false)
                        throw new PgpException("Failed to verify file.");

                    message = plainFact.NextPgpObject();
                }
                else if (!(message is PgpCompressedData))
                    throw new PgpException("File was not signed.");
            }

            if (message is PgpCompressedData cData)
            {
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                    message = of.NextPgpObject();
                }

                if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                {
                    PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

                    var verified = EncryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || EncryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
                    if (verified == false)
                        throw new PgpException("Failed to verify file.");

                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    await Streams.PipeAllAsync(unc, outputStream);
                }
                else
                {
                    throw new PgpException("File was not signed.");
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                await Streams.PipeAllAsync(unc, outputStream);

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        throw new PgpException("Message failed integrity check.");
                    }
                }
            }
            else
                throw new PgpException("File was not signed.");
        }

        #endregion DecryptAndVerifyAsync
        #region DecryptAndVerify

        /// <summary>
        /// PGP decrypt and verify a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        private void DecryptAndVerify(Stream inputStream, Stream outputStream)
        {
            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedDataList = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList)
                encryptedDataList = (PgpEncryptedDataList)obj;
            else if (obj is PgpCompressedData)
                message = (PgpCompressedData)obj;
            else
                encryptedDataList = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (encryptedDataList == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            if (encryptedDataList != null)
            {
                foreach (PgpPublicKeyEncryptedData pked in encryptedDataList.GetEncryptedDataObjects())
                {
                    privateKey = EncryptionKeys.FindSecretKey(pked.KeyId);

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

                message = plainFact.NextPgpObject();

                if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                {
                    PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

                    var verified = EncryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || EncryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
                    if (verified == false)
                        throw new PgpException("Failed to verify file.");

                    message = plainFact.NextPgpObject();
                }
                else if (!(message is PgpCompressedData))
                    throw new PgpException("File was not signed.");
            }

            if (message is PgpCompressedData cData)
            {
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                    message = of.NextPgpObject();
                }

                if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                {
                    PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];

                    var verified = EncryptionKeys.PublicKey.KeyId == pgpOnePassSignature.KeyId || EncryptionKeys.PublicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId);
                    if (verified == false)
                        throw new PgpException("Failed to verify file.");

                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
                else
                {
                    throw new PgpException("File was not signed.");
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
                throw new PgpException("File was not signed.");
        }

        #endregion DecryptAndVerify
        #region VerifyAsync

        private async Task<bool> VerifyAsync(Stream inputStream)
        {
            PgpPublicKey publicKey = EncryptionKeys.PublicKey;
            bool verified = false;

            System.IO.Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            if (pgpObject is PgpCompressedData)
            {
                PgpPublicKeyEncryptedData publicKeyED = Utilities.ExtractPublicKeyEncryptedData(encodedFile);

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == publicKeyED.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(publicKeyED.KeyId))
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

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == publicKeyED.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(publicKeyED.KeyId))
                {
                    verified = true;
                }
                else
                {
                    verified = false;
                }
                //PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)pgpObject;

                //foreach (PgpPublicKeyEncryptedData encryptedData in encryptedDataList.GetEncryptedDataObjects())
                //{
                //    encryptedData.GetDataStream(EncryptionKeys.PrivateKey);
                //    if (encryptedData.Verify())
                //    {
                //        verified = true;
                //        break;
                //    }
                //}
            }
            else if (pgpObject is PgpOnePassSignatureList)
            {
                PgpOnePassSignatureList pgpOnePassSignatureList = (PgpOnePassSignatureList)pgpObject;
                PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == pgpOnePassSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId))
                {
                    pgpOnePassSignature.InitVerify(publicKey);

                    int ch;
                    while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                    {
                        pgpOnePassSignature.Update((byte)ch);
                    }

                    try
                    {
                        PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

                        for (int i = 0; i < pgpSignatureList.Count; i++)
                        {
                            PgpSignature pgpSignature = pgpSignatureList[i];

                            if (pgpOnePassSignature.Verify(pgpSignature))
                            {
                                verified = true;
                                break;
                            }
                        }
                    }
                    catch
                    {
                        verified = false;
                    }
                }
                else
                {
                    verified = false;
                }
            }
            else if (pgpObject is PgpSignatureList)
            {
                PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObject;
                PgpSignature pgpSignature = pgpSignatureList[0];
                PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == pgpSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpSignature.KeyId))
                {
                    foreach (PgpSignature signature in publicKey.GetSignatures())
                    {
                        if (!verified)
                        {
                            pgpSignature.InitVerify(publicKey);

                            int ch;
                            while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                            {
                                pgpSignature.Update((byte)ch);
                            }

                            verified = pgpSignature.Verify();
                        }
                        else
                        {
                            break;
                        }
                    }
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

        #endregion VerifyAsync
        #region Verify

        private bool Verify(Stream inputStream)
        {
            PgpPublicKey publicKey = EncryptionKeys.PublicKey;
            bool verified = false;

            ArmoredInputStream encodedFile = new ArmoredInputStream(inputStream);
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            if (pgpObject is PgpCompressedData)
            {
                PgpCompressedData pgpCompressedData = (PgpCompressedData)pgpObject;
                PgpObjectFactory pgpCompressedFactory = new PgpObjectFactory(pgpCompressedData.GetDataStream());

                PgpOnePassSignatureList pgpOnePassSignatureList = (PgpOnePassSignatureList)pgpCompressedFactory.NextPgpObject();
                PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == pgpOnePassSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId))
                {
                    foreach (PgpSignature signature in publicKey.GetSignatures())
                    {
                        if (!verified)
                        {
                            pgpOnePassSignature.InitVerify(publicKey);

                            int ch;
                            while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                            {
                                pgpOnePassSignature.Update((byte)ch);
                            }

                            try
                            {
                                PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

                                for (int i = 0; i < pgpSignatureList.Count; i++)
                                {
                                    PgpSignature pgpSignature = pgpSignatureList[i];

                                    if (pgpOnePassSignature.Verify(pgpSignature))
                                    {
                                        verified = true;
                                        break;
                                    }
                                }
                            }
                            catch
                            {
                                verified = false;
                                break;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
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

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == publicKeyED.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(publicKeyED.KeyId))
                {
                    verified = true;
                }
                else
                {
                    verified = false;
                }
                //PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)pgpObject;

                //foreach (PgpPublicKeyEncryptedData encryptedData in encryptedDataList.GetEncryptedDataObjects())
                //{
                //    using (encryptedData.GetDataStream(EncryptionKeys.PrivateKey))
                //    {
                //        if (encryptedData.Verify())
                //        {
                //            verified = true;
                //            break;
                //        }
                //    }
                //}
            }
            else if (pgpObject is PgpOnePassSignatureList)
            {
                PgpOnePassSignatureList pgpOnePassSignatureList = (PgpOnePassSignatureList)pgpObject;
                PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
                Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

                // Verify against public key ID and that of any sub keys
                if (publicKey.KeyId == pgpOnePassSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpOnePassSignature.KeyId))
                {
                    pgpOnePassSignature.InitVerify(publicKey);

                    int ch;
                    while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                    {
                        pgpOnePassSignature.Update((byte)ch);
                    }

                    try
                    {
                        PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

                        for (int i = 0; i < pgpSignatureList.Count; i++)
                        {
                            PgpSignature pgpSignature = pgpSignatureList[i];

                            if (pgpOnePassSignature.Verify(pgpSignature))
                            {
                                verified = true;
                                break;
                            }
                        }
                    }
                    catch
                    {
                        verified = false;
                    }
                }
                else
                {
                    verified = false;
                }
            }
            else if (pgpObject is PgpSignatureList)
            {
               PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObject;
               PgpSignature pgpSignature = pgpSignatureList[0];
               PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
               Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

               // Verify against public key ID and that of any sub keys
               if (publicKey.KeyId == pgpSignature.KeyId || publicKey.GetKeySignatures().Cast<PgpSignature>().Select(x => x.KeyId).Contains(pgpSignature.KeyId))
               {
                   foreach (PgpSignature signature in publicKey.GetSignatures())
                   {
                       if (!verified)
                       {
                           pgpSignature.InitVerify(publicKey);

                           int ch;
                           while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                           {
                               pgpSignature.Update((byte)ch);
                           }

                            verified = pgpSignature.Verify();
                       }
                       else
                       {
                           break;
                       }
                   }
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

        #endregion Verify
        #region VerifyClearAsync

        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        private async Task<bool> VerifyClearAsync(Stream inputStream)
        {
            bool verified = false;

            using (MemoryStream outStream = new MemoryStream())
            {
                var publicKey = EncryptionKeys.PublicKey;
                PgpSignature pgpSignature;

                using (ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream))
                {
                    MemoryStream lineOut = new MemoryStream();
                    byte[] lineSep = LineSeparator;
                    int lookAhead = ReadInputLine(lineOut, armoredInputStream);

                    // Read past message to signature and store message in stream
                    if (lookAhead != -1 && armoredInputStream.IsClearText())
                    {
                        byte[] line = lineOut.ToArray();
                        await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        await outStream.WriteAsync(lineSep, 0, lineSep.Length);

                        while (lookAhead != -1 && armoredInputStream.IsClearText())
                        {
                            lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

                            line = lineOut.ToArray();
                            await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                            await outStream.WriteAsync(lineSep, 0, lineSep.Length);
                        }
                    }
                    else if (lookAhead != -1)
                    {
                        byte[] line = lineOut.ToArray();
                        await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        await outStream.WriteAsync(lineSep, 0, lineSep.Length);
                    }

                    // Get public key from correctly positioned stream and initialise for verification
                    PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
                    PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
                    pgpSignature = pgpSignatureList[0];
                    pgpSignature.InitVerify(publicKey);

                    // Read through message again and calculate signature
                    outStream.Position = 0;
                    lookAhead = ReadInputLine(lineOut, outStream);

                    ProcessLine(pgpSignature, lineOut.ToArray());

                    if (lookAhead != -1)
                    {
                        do
                        {
                            lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

                            pgpSignature.Update((byte)'\r');
                            pgpSignature.Update((byte)'\n');

                            ProcessLine(pgpSignature, lineOut.ToArray());
                        }
                        while (lookAhead != -1);
                    }

                    verified = pgpSignature.Verify();
                }
            }

            return verified;
        }

        #endregion VerifyClearAsync
        #region VerifyClear

        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        private bool VerifyClear(Stream inputStream)
        {
            bool verified = false;

            using (MemoryStream outStream = new MemoryStream())
            {
                var publicKey = EncryptionKeys.PublicKey;
                PgpSignature pgpSignature;

                using (ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream))
                {
                    MemoryStream lineOut = new MemoryStream();
                    byte[] lineSep = LineSeparator;
                    int lookAhead = ReadInputLine(lineOut, armoredInputStream);

                    // Read past message to signature and store message in stream
                    if (lookAhead != -1 && armoredInputStream.IsClearText())
                    {
                        byte[] line = lineOut.ToArray();
                        outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStream.Write(lineSep, 0, lineSep.Length);

                        while (lookAhead != -1 && armoredInputStream.IsClearText())
                        {
                            lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

                            line = lineOut.ToArray();
                            outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                            outStream.Write(lineSep, 0, lineSep.Length);
                        }
                    }
                    else if (lookAhead != -1)
                    {
                        byte[] line = lineOut.ToArray();
                        outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStream.Write(lineSep, 0, lineSep.Length);
                    }

                    // Get public key from correctly positioned stream and initialise for verification
                    PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
                    PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
                    pgpSignature = pgpSignatureList[0];
                    pgpSignature.InitVerify(publicKey);

                    // Read through message again and calculate signature
                    outStream.Position = 0;
                    lookAhead = ReadInputLine(lineOut, outStream);

                    ProcessLine(pgpSignature, lineOut.ToArray());

                    if (lookAhead != -1)
                    {
                        do
                        {
                            lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

                            pgpSignature.Update((byte)'\r');
                            pgpSignature.Update((byte)'\n');

                            ProcessLine(pgpSignature, lineOut.ToArray());
                        }
                        while (lookAhead != -1);
                    }

                    verified = pgpSignature.Verify();
                }
            }

            return verified;
        }

        #endregion VerifyClear
        #region WriteOutputAndSign

        private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = await inputFilePath.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await literalOut.WriteAsync(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            signatureGenerator.Generate().Encode(compressedOut);
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

        private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, Stream inputStream, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await literalOut.WriteAsync(buf, 0, length);
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

        #endregion WriteOutputAndSign
        #region ChainEncryptedOut

        private Stream ChainEncryptedOut(Stream outputStream, IEncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            foreach (PgpPublicKey publicKey in encryptionKeys.PublicKeys)
            {
                encryptedDataGenerator.AddMethod(publicKey);
            }

            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            foreach (PgpPublicKey publicKey in EncryptionKeys.PublicKeys)
            {
                encryptedDataGenerator.AddMethod(publicKey);
            }

            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        #endregion ChainEncryptedOut
        #region ChainCompressedOut

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

        #endregion ChainCompressedOut
        #region ChainLiteralOut

        private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file.Name, file.Length, DateTime.UtcNow);
        }

        #endregion ChainLiteralOut
        #region ChainLiteralStreamOut

        private Stream ChainLiteralStreamOut(Stream compressedOut, Stream inputStream, string name)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length, DateTime.UtcNow);
        }

        #endregion ChainLiteralStreamOut
        #region InitSignatureGenerator

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, IEncryptionKeys encryptionKeys)
        {
            PublicKeyAlgorithmTag tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
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

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {
            PublicKeyAlgorithmTag tag = EncryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, EncryptionKeys.PrivateKey);
            foreach (string userId in EncryptionKeys.SecretKey.PublicKey.GetUserIds())
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

        #endregion InitSignatureGenerator
        #region InitClearSignatureGenerator

        private PgpSignatureGenerator InitClearSignatureGenerator(ArmoredOutputStream armoredOutputStream, IEncryptionKeys encryptionKeys)
        {
            PublicKeyAlgorithmTag tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
            pgpSignatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, encryptionKeys.PrivateKey);
            armoredOutputStream.BeginClearText(HashAlgorithmTag);
            foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            return pgpSignatureGenerator;
        }

        private PgpSignatureGenerator InitClearSignatureGenerator(ArmoredOutputStream armoredOutputStream)
        {
            PublicKeyAlgorithmTag tag = EncryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
            pgpSignatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, EncryptionKeys.PrivateKey);
            armoredOutputStream.BeginClearText(HashAlgorithmTag);
            foreach (string userId in EncryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            return pgpSignatureGenerator;
        }

        #endregion InitClearSignatureGenerator
        #region Misc Utilities
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
                    bool armor, bool emitVersion)
        {
            if (secretOut == null)
                throw new ArgumentException("secretOut");
            if (publicOut == null)
                throw new ArgumentException("publicOut");

            ArmoredOutputStream secretOutArmored;
            if (armor)
            {
                secretOutArmored = new ArmoredOutputStream(secretOut);
                if (!emitVersion)
                {
                    secretOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
                }
                secretOut = secretOutArmored;
            }
            else
            {
                secretOutArmored = null;
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignatureType,
                PublicKeyAlgorithm,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                identity,
                SymmetricKeyAlgorithm,
                passPhrase,
                null,
                null,
                new SecureRandom()
                //                ,"BC"
                );

                secretKey.Encode(secretOut);

            secretOutArmored?.Dispose();

            ArmoredOutputStream publicOutArmored;
            if (armor)
            {
                publicOutArmored = new ArmoredOutputStream(publicOut);
                if (!emitVersion)
                {
                    publicOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
                }
                publicOut = publicOutArmored;
            }
            else
            {
                publicOutArmored = null;
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOutArmored?.Dispose();
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

        private static int ReadInputLine(Stream encodedFile)
        {
            int lookAhead = -1;
            int character;

            while ((character = encodedFile.ReadByte()) >= 0)
            {
                if (character == '\r' || character == '\n')
                {
                    lookAhead = ReadPassedEol(character, encodedFile);
                    break;
                }
            }

            return lookAhead;
        }

        private static int ReadInputLine(MemoryStream streamOut, Stream encodedFile)
        {
            streamOut.SetLength(0);

            int lookAhead = -1;
            int character;

            while ((character = encodedFile.ReadByte()) >= 0)
            {
                streamOut.WriteByte((byte)character);
                if (character == '\r' || character == '\n')
                {
                    lookAhead = ReadPassedEol(streamOut, character, encodedFile);
                    break;
                }
            }

            return lookAhead;
        }

        private static int ReadInputLine(MemoryStream streamOut, int lookAhead, Stream encodedFile)
        {
            streamOut.SetLength(0);

            int character = lookAhead;

            do
            {
                streamOut.WriteByte((byte)character);
                if (character == '\r' || character == '\n')
                {
                    lookAhead = ReadPassedEol(streamOut, character, encodedFile);
                    break;
                }
            }
            while ((character = encodedFile.ReadByte()) >= 0);

            if (character < 0)
            {
                lookAhead = -1;
            }

            return lookAhead;
        }

        private static int ReadPassedEol(int lastCharacter, Stream encodedFile)
        {
            int lookAhead = encodedFile.ReadByte();

            if (lastCharacter == '\r' && lookAhead == '\n')
            {
                lookAhead = encodedFile.ReadByte();
            }

            return lookAhead;
        }

        private static int ReadPassedEol(MemoryStream streamOut, int lastCharacter, Stream encodedFile)
        {
            int lookAhead = encodedFile.ReadByte();

            if (lastCharacter == '\r' && lookAhead == '\n')
            {
                streamOut.WriteByte((byte)lookAhead);
                lookAhead = encodedFile.ReadByte();
            }

            return lookAhead;
        }

        private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }

        private static int GetLengthWithoutWhiteSpace(byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }

        private static bool IsWhiteSpace(byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }

        private static bool IsLineEnding(byte b)
        {
            return b == '\r' || b == '\n';
        }

        private static void ProcessLine(PgpSignature sig, byte[] line)
        {
            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            int length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sig.Update(line, 0, length);
            }
        }

        private static byte[] LineSeparator
        {
            get { return Encoding.ASCII.GetBytes(Environment.NewLine); }
        }

        public void Dispose()
        {
        }

        # endregion Misc Utilities
        #endregion Private helpers
    }
}
