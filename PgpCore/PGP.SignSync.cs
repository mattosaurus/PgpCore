using PgpCore.Abstractions;
using System.Collections.Generic;
using System.IO;

namespace PgpCore
{
    public partial class PGP : ISignSync
    {
        #region Sign

        /// <summary>
        /// Sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public void Sign(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => SignAsync(inputFile, outputFile, armor, name, headers, oldFormat).GetAwaiter().GetResult();

        /// <summary>
        /// Sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="name">Name of signed file in message, defaults to the stream name if the stream is a FileStream, otherwise to "name"</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public void Sign(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => SignAsync(inputStream, outputStream, armor, name, headers, oldFormat).GetAwaiter().GetResult();

        /// <summary>
        /// Sign the string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="name">Name of signed file in message, defaults to "name"</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public string Sign(
            string input,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => SignAsync(input, name, headers, oldFormat).GetAwaiter().GetResult();

        public void SignFile(FileInfo inputFile, FileInfo outputFile, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => Sign(inputFile, outputFile, armor, name, headers, oldFormat);

        public void SignStream(Stream inputStream, Stream outputStream, bool armor = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => Sign(inputStream, outputStream, armor, name, headers, oldFormat);

        public string SignArmoredString(string input, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => Sign(input, name, headers, oldFormat);

        #endregion Sign

        #region ClearSign

        /// <summary>
        /// Clear sign the file pointed to by unencryptedFileInfo
        /// </summary>
        /// <param name="inputFile">Plain data file to be signed</param>
        /// <param name="outputFile">Output PGP signed file</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void ClearSign(
            FileInfo inputFile,
            FileInfo outputFile,
            IDictionary<string, string> headers = null) => ClearSignAsync(inputFile, outputFile, headers).GetAwaiter().GetResult();

        /// <summary>
        /// Clear sign the provided stream
        /// </summary>
        /// <param name="inputStream">Plain data stream to be signed</param>
        /// <param name="outputStream">Output PGP signed stream</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public void ClearSign(
            Stream inputStream,
            Stream outputStream,
            IDictionary<string, string> headers = null) => ClearSignAsync(inputStream, outputStream, headers).GetAwaiter().GetResult();

        /// <summary>
        /// Clear sign the provided string
        /// </summary>
        /// <param name="input">Plain string to be signed</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        public string ClearSign(
            string input,
            IDictionary<string, string> headers = null) => ClearSignAsync(input, headers).GetAwaiter().GetResult();

        public void ClearSignFile(FileInfo inputFile, FileInfo outputFile, IDictionary<string, string> headers = null) => ClearSign(inputFile, outputFile, headers);

        public void ClearSignStream(Stream inputStream, Stream outputStream, IDictionary<string, string> headers = null) => ClearSign(inputStream, outputStream, headers);

        public string ClearSignArmoredString(string input, IDictionary<string, string> headers = null) => ClearSign(input, headers);

        #endregion ClearSign
    }
}
