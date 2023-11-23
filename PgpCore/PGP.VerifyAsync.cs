using PgpCore.Abstractions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IVerifyAsync
    {
        #region VerifyFileAsync

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputFile contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<bool> VerifyFileAsync(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            {
                VerificationResult verificationResult = await VerifyAsync(inputStream, throwIfEncrypted);
                return verificationResult.IsVerified;
            }
        }

        #endregion VerifyFileAsync

        #region VerifyStreamAsync

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<bool> VerifyStreamAsync(Stream inputStream, bool throwIfEncrypted = false)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            VerificationResult verificationResult = await VerifyAsync(inputStream, throwIfEncrypted);
            return verificationResult.IsVerified;
        }

        #endregion VerifyStreamAsync

        #region VerifyArmoredStringAsync

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<bool> VerifyArmoredStringAsync(string input, bool throwIfEncrypted = false)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            {
                return await VerifyStreamAsync(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyArmoredStringAsync

        #region VerifyClearFileAsync

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        public async Task<bool> VerifyClearFileAsync(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            using (Stream inputStream = inputFile.OpenRead())
                return await VerifyClearAsync(inputStream);
        }

        #endregion VerifyClearFileAsync

        #region VerifyClearStreamAsync

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        public async Task<bool> VerifyClearStreamAsync(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return await VerifyClearAsync(inputStream);
        }

        #endregion VerifyClearStreamAsync

        #region VerifyClearArmoredStringAsync

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public async Task<bool> VerifyClearArmoredStringAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
                return await VerifyClearStreamAsync(inputStream);
        }

        #endregion VerifyClearArmoredStringAsync

        #region VerifyAndReadClearFileAsync

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="input">Clear signed file to be verified</param>
        public async Task<VerificationResult> VerifyAndReadClearFileAsync(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = await VerifyClearAsync(inputStream, outputStream);

                outputStream.Position = 0;
                using (StreamReader reader = new StreamReader(outputStream))
                {
                    string message = reader.ReadToEnd();
                    return new VerificationResult(verified, message);
                }
            }
        }
        #endregion VerifyAndReadClearFileAsync

        #region VerifyAndReadClearStreamAsync

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="input">Clear signed stream to be verified</param>
        public async Task<VerificationResult> VerifyAndReadClearStreamAsync(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            using (Stream outputStream = new MemoryStream())
            {
                bool verified = await VerifyClearAsync(inputStream, outputStream);

                outputStream.Position = 0;
                using (StreamReader reader = new StreamReader(outputStream))
                {
                    string message = reader.ReadToEnd();
                    return new VerificationResult(verified, message);
                }
            }
        }

        #endregion VerifyAndReadClearStreamAsync

        #region VerifyAndReadClearArmoredStringAsync

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public async Task<VerificationResult> VerifyAndReadClearArmoredStringAsync(string input)
        {
            if (input == null)
                throw new ArgumentNullException("input");

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                bool verified = await VerifyClearAsync(inputStream, outputStream);

                outputStream.Position = 0;
                using (StreamReader reader = new StreamReader(outputStream))
                {
                    string message = reader.ReadToEnd();
                    return new VerificationResult(verified, message);
                }
            }
        }

        #endregion VerifyAndReadClearArmoredStringAsync

        #region VerifyAndReadSignedFileAsync

        /// <summary>
        /// PGP verify a given signed file.
        /// </summary>
        /// <param name="inputFile">Signed file to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputFile contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<VerificationResult> VerifyAndReadSignedFileAsync(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            using (Stream inputStream = inputFile.OpenRead())
            {
                return await VerifyAsync(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyAndReadSignedFileAsync

        #region VerifyAndReadSignedStreamAsync

        /// <summary>
        /// PGP verify a given signed stream.
        /// </summary>
        /// <param name="inputStream">Signed stream to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<VerificationResult> VerifyAndReadSignedStreamAsync(Stream inputStream, bool throwIfEncrypted = false)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            return await VerifyAsync(inputStream, throwIfEncrypted);
        }

        #endregion VerifyAndReadSignedStreamAsync

        #region VerifyAndReadSignedArmoredStringAsync

        /// <summary>
        /// PGP verify a given signed string.
        /// </summary>
        /// <param name="input">Signed string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if input contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<VerificationResult> VerifyAndReadSignedArmoredStringAsync(string input, bool throwIfEncrypted = false)
        {
            if (input == null)
                throw new ArgumentNullException("input");

            using (Stream inputStream = await input.GetStreamAsync())
            {
                return await VerifyAsync(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyAndReadSignedArmoredStringAsync
    }
}
