using System.Collections.Generic;
using System.IO;
using PgpCore.Abstractions;

namespace PgpCore
{
    public partial class PGP : IEncryptSync
    {
        #region Encrypt
        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be encrypted</param>
        /// <param name="outputFile">Output PGP encrypted file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public void Encrypt(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => EncryptAsync(inputFile, outputFile, armor, withIntegrityCheck, name, headers, oldFormat).GetAwaiter().GetResult();

        /// <summary>
        /// PGP Encrypt the stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted</param>
        /// <param name="outputStream">Output PGP encrypted stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public void Encrypt(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => EncryptAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers, oldFormat).GetAwaiter().GetResult();

        /// <summary>
        /// PGP Encrypt the string.
        /// </summary>
        /// <param name="input">Plain string to be encrypted</param>
        /// <param name="withIntegrityCheck">True, to perform integrity packet check on input file. Otherwise, false</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public string Encrypt(
            string input,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => EncryptAsync(input, withIntegrityCheck, name, headers, oldFormat).GetAwaiter().GetResult();

        public string EncryptArmoredString(string input, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => Encrypt(input, withIntegrityCheck, name, headers, oldFormat);

        public void EncryptFile(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => Encrypt(inputFile, outputFile, armor, withIntegrityCheck, name, headers, oldFormat);

        public void EncryptStream(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => Encrypt(inputStream, outputStream, armor, withIntegrityCheck, name, headers, oldFormat);

        #endregion Encrypt

        #region EncryptAndSign

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFile">Plain data file path to be encrypted and signed</param>
        /// <param name="outputFile">Output PGP encrypted and signed file</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public void EncryptAndSign(
            FileInfo inputFile,
            FileInfo outputFile,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => EncryptAndSignAsync(inputFile, outputFile, armor, withIntegrityCheck, name, headers, oldFormat).GetAwaiter().GetResult();

        /// <summary>
        /// Encrypt and sign the stream pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputStream">Plain data stream to be encrypted and signed</param>
        /// <param name="outputStream">Output PGP encrypted and signed stream</param>
        /// <param name="armor">True, means a binary data representation as an ASCII-only text. Otherwise, false</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public void EncryptAndSign(
            Stream inputStream,
            Stream outputStream,
            bool armor = true,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => EncryptAndSignAsync(inputStream, outputStream, armor, withIntegrityCheck, name, headers, oldFormat).GetAwaiter().GetResult();

        /// <summary>
        /// Encrypt and sign the string
        /// </summary>
        /// <param name="input">Plain string to be encrypted and signed</param>
        /// <param name="withIntegrityCheck">True to include integrity packet during signing</param>
        /// <param name="name">Name of encrypted file in message, defaults to the input file name</param>
        /// <param name="headers">Optional headers to be added to the output</param>
        /// <param name="oldFormat">True, to use old format for encryption if you need compatibility with PGP 2.6.x. Otherwise, false</param>
        public string EncryptAndSign(
            string input,
            bool withIntegrityCheck = true,
            string name = null,
            IDictionary<string, string> headers = null,
            bool oldFormat = false) => EncryptAndSignAsync(input, withIntegrityCheck, name, headers, oldFormat).GetAwaiter().GetResult();

        public string EncryptArmoredStringAndSign(string input, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => EncryptAndSign(input, withIntegrityCheck, name, headers, oldFormat);

        public void EncryptFileAndSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => EncryptAndSign(inputFile, outputFile, armor, withIntegrityCheck, name, headers, oldFormat);

        public void EncryptStreamAndSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false) => EncryptAndSign(inputStream, outputStream, armor, withIntegrityCheck, name, headers, oldFormat);

        #endregion EncryptAndSign
    }
}
