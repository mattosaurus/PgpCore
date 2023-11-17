using Org.BouncyCastle.Bcpg;
using PgpCore.Abstractions;
using PgpCore.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : ISignAsync
    {
        #region SignFileAsync
        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        public async Task SignFileAsync(FileInfo inputFile, FileInfo outputFile,
            bool armor = true)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        await OutputSignedAsync(inputFile, armoredOutputStream);
                    }
                }
                else
                    await OutputSignedAsync(inputFile, outputStream);
            }
        }

        #endregion SignFileAsync

        #region SignStreamAsync
        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task SignStreamAsync(Stream inputStream, Stream outputStream,
            bool armor = true, string name = DefaultFileName)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (name == DefaultFileName && inputStream is FileStream fileStream)
            {
                string inputFilePath = fileStream.Name;
                name = Path.GetFileName(inputFilePath);
            }

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    await OutputSignedAsync(inputStream, armoredOutputStream, name);
                }
            }
            else
                await OutputSignedAsync(inputStream, outputStream, name);
        }

        #endregion SignStreamAsync

        #region SignArmoredStringAsync

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        public async Task<string> SignArmoredStringAsync(string input,
            string name = DefaultFileName)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await SignStreamAsync(inputStream, outputStream, true, name);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        #endregion SignArmoredStringAsync

        #region ClearSignFileAsync
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
                throw new FileNotFoundException($"Input file [{inputFile.Name}] does not exist.");

            using (Stream outputStream = outputFile.OpenWrite())
            {
                await OutputClearSignedAsync(inputFile, outputStream);
            }
        }

        #endregion ClearSignFileAsync

        #region ClearSignStreamAsync
        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
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

        #region ClearSignArmoredStringAsync
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
    }
}
