using Org.BouncyCastle.Bcpg;
using PgpCore.Abstractions;
using PgpCore.Extensions;
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
        #region SignAsync
        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public async Task SignAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false)
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

            using (Stream outputStream = outputFile.OpenWrite())
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
                    {
                        await OutputSignedAsync(inputFile, armoredOutputStream, name, oldFormat);
                    }
                }
                else
                    await OutputSignedAsync(inputFile, outputStream, name, oldFormat);
            }
        }

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the stream name if the stream is a FileStream, otherwise to "name"</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public async Task SignAsync(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (string.IsNullOrEmpty(name) && inputStream is FileStream fileStream)
                name = Path.GetFileName(fileStream.Name);
            else if (string.IsNullOrEmpty(name))
                name = DefaultFileName;
            if (headers == null)
                headers = new Dictionary<string, string>();
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            if (armor)
            {
                using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
                {
                    await OutputSignedAsync(inputStream, armoredOutputStream, name, oldFormat);
                }
            }
            else
                await OutputSignedAsync(inputStream, outputStream, name, oldFormat);
        }

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="name">Name of signed file in message, defaults to "name"</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public async Task<string> SignAsync(
            string input,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false)
        {
            if (string.IsNullOrEmpty(name))
                name = DefaultFileName;
            if (headers == null)
                headers = new Dictionary<string, string>();

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await SignAsync(inputStream, outputStream, true, name, headers, oldFormat);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public async Task SignFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => await SignAsync(inputFile, outputFile, armor, name, headers, oldFormat);

        public async Task SignStreamAsync(Stream inputStream, Stream outputStream, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => await SignAsync(inputStream, outputStream, armor, name, headers, oldFormat);

        public async Task<string> SignArmoredStringAsync(string input, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => await SignAsync(input, name, headers, oldFormat);

        #endregion SignAsync

        #region ClearSignAsync

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task ClearSignAsync(
            FileInfo inputFile,
            FileInfo outputFile,
            IDictionary<string, string> headers = null)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (headers == null)
                headers = new Dictionary<string, string>();

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.Name}] does not exist.");

            using (Stream outputStream = outputFile.OpenWrite())
            {
                await OutputClearSignedAsync(inputFile, outputStream, headers);
            }
        }

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task ClearSignAsync(
            Stream inputStream,
            Stream outputStream,
            IDictionary<string, string> headers = null)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");
            if (headers == null)
                headers = new Dictionary<string, string>();
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            await OutputClearSignedAsync(inputStream, outputStream, headers);
        }

        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public async Task<string> ClearSignAsync(
            string input,
            IDictionary<string, string> headers = null)
        {
            if (headers == null)
                headers = new Dictionary<string, string>();

            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await ClearSignAsync(inputStream, outputStream, headers);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public async Task ClearSignFileAsync(FileInfo inputFile, FileInfo outputFile, IDictionary<string, string> headers = null) => await ClearSignAsync(inputFile, outputFile, headers);

        public async Task ClearSignStreamAsync(Stream inputStream, Stream outputStream, IDictionary<string, string> headers = null) => await ClearSignAsync(inputStream, outputStream, headers);

        public async Task<string> ClearSignArmoredStringAsync(string input, IDictionary<string, string> headers = null) => await ClearSignAsync(input, headers);

        #endregion ClearSignAsync
    }
}
