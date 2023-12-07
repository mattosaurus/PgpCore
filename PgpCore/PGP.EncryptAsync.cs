using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using PgpCore.Helpers;
using PgpCore.Models;
using PgpCore.Abstractions;
using PgpCore.Extensions;

namespace PgpCore
{
    public partial class PGP : IEncryptAsync
    {
        #region EncryptAsync

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task EncryptAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (string.IsNullOrEmpty(name))
                name = Path.GetFileName(inputFile.Name);
            if (headers == null)
                headers = new Dictionary<string, string>();
            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (FileStream inputStream = inputFile.OpenRead())
            using (Stream outputStream = outputFile.OpenWrite())
                await EncryptAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers);
        }

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task EncryptAsync(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (string.IsNullOrEmpty(name) && inputStream is FileStream fileStream)
                Path.GetFileName(fileStream.Name);
            else if (string.IsNullOrEmpty(name))
                name = DefaultFileName;
            if (headers == null)
                headers = new Dictionary<string, string>();
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream, headers);
            }

            PgpEncryptedDataGenerator pk =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
            foreach (PgpPublicKeyRingWithPreferredKey publicKeyRing in EncryptionKeys.PublicKeyRings)
            {
                PgpPublicKey publicKey = publicKeyRing.PreferredEncryptionKey ?? publicKeyRing.DefaultEncryptionKey;
                pk.AddMethod(publicKey);
            }

            Stream @out = pk.Open(outputStream, new byte[1 << 16]);

            if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
            {
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithm);
                await Utilities.WriteStreamToLiteralDataAsync(comData.Open(@out), FileTypeToChar(), inputStream, name);
            }
            else
                await Utilities.WriteStreamToLiteralDataAsync(@out, FileTypeToChar(), inputStream, name);

            @out.Close();

            if (armor)
            {
                outputStream.Close();
            }
        }

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task<string> EncryptAsync(
            string input,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null)
        {
            if (string.IsNullOrEmpty(name))
                name = DefaultFileName;
            if (headers == null)
                headers = new Dictionary<string, string>();

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public async Task EncryptFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null) => await EncryptAsync(inputFile, outputFile, armor, withIntegrityCheck, name, headers);

        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null) => await EncryptAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers);

        public async Task<string> EncryptArmoredStringAsync(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null) => await EncryptAsync(input, armor, withIntegrityCheck, name, headers);

        #endregion EncryptAsync

        #region EncryptAndSignAsync

        /// <summary>
        /// Encrypt and sign the file pointed to by the unencrypted FileInfo.
        /// This method will include the signature within the encrypted message and is different from first encrypting a file and then signing it.
        /// </summary>
        /// <param name="inputFile">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file path</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task EncryptAndSignAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFilePath");
            if (outputFile == null)
                throw new ArgumentException("OutputFilePath");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (string.IsNullOrEmpty(name))
                name = Path.GetFileName(inputFile.Name);
            if (headers == null)
                headers = new Dictionary<string, string>();

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
                    {
                        await OutputEncryptedAsync(inputFile, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    await OutputEncryptedAsync(inputFile, outputStream, withIntegrityCheck, name);
            }
        }

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencrypted Stream.
        /// This method will include the signature within the encrypted message and is different from first encrypting a file and then signing it.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task EncryptAndSignAsync(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");
            if (string.IsNullOrEmpty(name) && inputStream is FileStream fileStream)
                Path.GetFileName(fileStream.Name);
            else if (string.IsNullOrEmpty(name))
                name = DefaultFileName;
            if (headers == null)
                headers = new Dictionary<string, string>();

            if (armor)
            {
                using (var armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
                {
                    await OutputEncryptedAsync(inputStream, armoredOutputStream, withIntegrityCheck, name);
                }
            }
            else
                await OutputEncryptedAsync(inputStream, outputStream, withIntegrityCheck, name);
        }

        /// <summary>
        /// Encrypt and sign the string.
        /// This method will include the signature within the encrypted message and is different from first encrypting a file and then signing it.
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task<string> EncryptAndSignAsync(
            string input,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null)
        {
            if (string.IsNullOrEmpty(name))
                name = DefaultFileName;
            if (headers == null)
                headers = new Dictionary<string, string>();

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptAndSignAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public async Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null) => await EncryptAndSignAsync(inputFile, outputFile, armor, withIntegrityCheck, name, headers);

        public async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null) => await EncryptAndSignAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers);

        public async Task<string> EncryptArmoredStringAndSignAsync(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null) => await EncryptAndSignAsync(input, armor, withIntegrityCheck, name, headers);

        #endregion EncryptAndSignAsync
    }
}
