using PgpCore.Abstractions;
using PgpCore.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IDecryptAsync
    {
        #region DecryptFileAsync

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
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptStreamAsync(inputStream, outStream);
        }

        #endregion DecryptFileAsync

        #region DecryptStreamAsync

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
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            await DecryptAsync(inputStream, outputStream);
            return outputStream;
        }

        #endregion DecryptStreamAsync

        #region DecryptArmoredStringAsync

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

        #region DecryptFileAndVerifyAsync

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file path</param>
        public async Task DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                await DecryptStreamAndVerifyAsync(inputStream, outStream);
        }

        #endregion DecryptFileAndVerifyAsync

        #region DecryptStreamAndVerifyAsync

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
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            await DecryptAndVerifyAsync(inputStream, outputStream);
            return outputStream;
        }

        #endregion DecryptStreamAndVerifyAsync

        #region DecryptArmoredStringAndVerifyAsync

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
    }
}
