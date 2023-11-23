using PgpCore.Abstractions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PgpCore
{
    public partial class PGP : IVerifySync
    {
        #region VerifyFile

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="throwIfEncrypted">Throw if file contains encrypted data. Otherwise, verify encryption key.</param>
        public bool VerifyFile(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
                return Verify(inputStream, throwIfEncrypted).IsVerified;
        }

        #endregion VerifyFile

        #region VerifyStream

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="throwIfEncrypted">Throws if the input stream is encrypted data. Otherwise, verifies the encryption key.</param>
        public bool VerifyStream(Stream inputStream, bool throwIfEncrypted = false)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return Verify(inputStream, throwIfEncrypted).IsVerified;
        }

        #endregion VerifyStream

        #region VerifyArmoredString

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public bool VerifyArmoredString(string input, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = input.GetStream())
            {
                return VerifyStream(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyArmoredString

        #region VerifyClearFile

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        public bool VerifyClearFile(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            using (Stream inputStream = inputFile.OpenRead())
                return VerifyClear(inputStream);
        }

        #endregion VerifyClearFile

        #region VerifyClearStream

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed stream to be verified</param>
        public bool VerifyClearStream(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return VerifyClear(inputStream);
        }

        #endregion VerifyClearStream

        #region VerifyClearArmoredString

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public bool VerifyClearArmoredString(string input)
        {
            using (Stream inputStream = input.GetStream())
                return VerifyClearStream(inputStream);
        }

        #endregion VerifyClearArmoredString

        #region VerifyAndReadClearFile

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="input">Clear signed file to be verified</param>
        public VerificationResult VerifyAndReadClearFile(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = VerifyClear(inputStream, outputStream);

                outputStream.Position = 0;
                using (StreamReader reader = new StreamReader(outputStream))
                {
                    string message = reader.ReadToEnd();
                    return new VerificationResult(verified, message);
                }
            }
        }

        #endregion VerifyAndReadClearFile

        #region VerifyAndReadClearStream

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="input">Clear signed stream to be verified</param>
        public VerificationResult VerifyAndReadClearStream(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            using (Stream outputStream = new MemoryStream())
            {
                bool verified = VerifyClear(inputStream, outputStream);

                outputStream.Position = 0;
                using (StreamReader reader = new StreamReader(outputStream))
                {
                    string message = reader.ReadToEnd();
                    return new VerificationResult(verified, message);
                }
            }
        }

        #endregion VerifyAndReadClearStream

        #region VerifyAndReadClearArmoredString

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public VerificationResult VerifyAndReadClearArmoredString(string input)
        {
            if (input == null)
                throw new ArgumentNullException("input");

            using (Stream inputStream = input.GetStream())
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = VerifyClear(inputStream, outputStream);

                outputStream.Position = 0;
                using (StreamReader reader = new StreamReader(outputStream))
                {
                    string message = reader.ReadToEnd();
                    return new VerificationResult(verified, message);
                }
            }
        }

        #endregion VerifyAndReadClearArmoredString

        #region VerifyAndReadSignedFile

        /// <summary>
        /// PGP verify a given signed file.
        /// </summary>
        /// <param name="inputFile">Signed file to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputFile contains encrypted data. Otherwise, verify encryption key.</param>
        public VerificationResult VerifyAndReadSignedFile(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            using (Stream inputStream = inputFile.OpenRead())
            {
                return Verify(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyAndReadSignedFile

        #region VerifyAndReadSignedStream

        /// <summary>
        /// PGP verify a given signed stream.
        /// </summary>
        /// <param name="inputStream">Signed stream to be verified</param>
        /// <param name="throwIfEncrypted">Throw if the stream contains encrypted data. Otherwise, verify encryption key.</param>
        public VerificationResult VerifyAndReadSignedStream(Stream inputStream, bool throwIfEncrypted = false)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return Verify(inputStream, throwIfEncrypted);
        }

        #endregion VerifyAndReadSignedStream

        #region VerifyAndReadSignedArmoredString

        /// <summary>
        /// PGP verify a given signed string.
        /// </summary>
        /// <param name="input">Signed string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if the string contains encrypted data. Otherwise, verify encryption key.</param>
        public VerificationResult VerifyAndReadSignedArmoredString(string input, bool throwIfEncrypted = false)
        {
            if (input == null)
                throw new ArgumentNullException("input");

            using (Stream inputStream = input.GetStream())
            {
                return Verify(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyAndReadSignedArmoredString
    }
}
