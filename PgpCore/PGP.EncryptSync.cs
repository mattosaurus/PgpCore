using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using PgpCore.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PgpCore.Models;
using PgpCore.Abstractions;

namespace PgpCore
{
    public partial class PGP : IEncryptSync
    {
        #region EncryptFile
        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void EncryptFile(
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
                EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name, headers);
        }

        #endregion EncryptFile

        #region EncryptStream

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void EncryptStream(
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
                Utilities.WriteStreamToLiteralData(comData.Open(@out), FileTypeToChar(), inputStream, name);
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

        #region EncryptArmoredString

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public string EncryptArmoredString(
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

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStream(inputStream, outputStream, armor, withIntegrityCheck, name, headers);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        #endregion EncryptArmoredString

        #region EncryptFileAndSign

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void EncryptFileAndSign(
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
                    using (var armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
                    {
                        OutputEncrypted(inputFile, armoredOutputStream, withIntegrityCheck, name);
                    }
                }
                else
                    OutputEncrypted(inputFile, outputStream, withIntegrityCheck, name);
            }
        }

        #endregion EncryptFileAndSign

        #region EncryptStreamAndSign

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void EncryptStreamAndSign(
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
                    OutputEncrypted(inputStream, armoredOutputStream, withIntegrityCheck, name);
                }
            }
            else
                OutputEncrypted(inputStream, outputStream, withIntegrityCheck, name);
        }

        #endregion EncryptStreamAndSign

        #region EncryptArmoredStringAndSign

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public string EncryptArmoredStringAndSign(
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

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                EncryptStreamAndSign(inputStream, outputStream, armor, withIntegrityCheck, name, headers);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream.GetString();
            }
        }

        #endregion EncryptArmoredStringAndSign
    }
}
