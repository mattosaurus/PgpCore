using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.Zlib;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IInspectAsync
    {
        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="inputStream">The input stream containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public async Task<PgpInspectResult> InspectAsync(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (inputStream.CanSeek && inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream", nameof(inputStream));

            // Inspection reads the input several times (armor sniff, headers, packet walk), so a
            // non-seekable stream (e.g. a network stream) must be buffered up front.
            if (!inputStream.CanSeek)
            {
                MemoryStream seekableStream = new MemoryStream();
                await inputStream.CopyToAsync(seekableStream).ConfigureAwait(false);
                seekableStream.Position = 0;
                inputStream = seekableStream;
            }

            bool isArmored = await IsArmoredAsync(inputStream).ConfigureAwait(false);
            Dictionary<string, string> messageHeaders = null;
            
            if (isArmored)
                messageHeaders = await GetMessageHeadersAsync(inputStream).ConfigureAwait(false);

            PgpInspectBaseResult pgpInspectBaseResult = GetPgpInspectBaseResult(inputStream);

            return new PgpInspectResult(
                pgpInspectBaseResult,
                isArmored,
                messageHeaders
                );
        }

        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="inputFile">The input file containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public async Task<PgpInspectResult> InspectAsync(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (FileStream inputStream = inputFile.OpenRead())
                return await InspectAsync(inputStream).ConfigureAwait(false);
        }

        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="input">The input string containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public async Task<PgpInspectResult> InspectAsync(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException($"{nameof(input)} cannot be null or empty.", nameof(input));

            using (Stream inputStream = await input.GetStreamAsync().ConfigureAwait(false))
            {
                return await InspectAsync(inputStream).ConfigureAwait(false);
            }
        }

        private async Task<bool> IsArmoredAsync(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            byte[] headerBytes = new byte[26];
            await stream.ReadAsync(headerBytes, 0, 26).ConfigureAwait(false);
            return IsArmored(headerBytes);
        }

        private async Task<Dictionary<string, string>> GetMessageHeadersAsync(Stream inputStream)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();

            StreamReader reader = new StreamReader(inputStream);
            string line;

            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
                if (line.StartsWith("-----"))
                {
                    break;
                }

                int colonIndex = line.IndexOf(':');
                if (colonIndex != -1)
                {
                    string key = line.Substring(0, colonIndex).Trim();
                    string value = line.Substring(colonIndex + 1).Trim();
                    headers[key] = value;
                }
            }

            return headers;
        }
    }
}
