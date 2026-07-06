using PgpCore.Abstractions;
using System.IO;

namespace PgpCore
{
    public partial class PGP : IDecryptSync
    {
        #region Decrypt

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        public void Decrypt(FileInfo inputFile, FileInfo outputFile) => DecryptAsync(inputFile, outputFile).GetAwaiter().GetResult();

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <returns></returns>
        public void Decrypt(Stream inputStream, Stream outputStream) => DecryptAsync(inputStream, outputStream).GetAwaiter().GetResult();

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        public string Decrypt(string input) => DecryptAsync(input).GetAwaiter().GetResult();

        public string DecryptArmoredString(string input) => Decrypt(input);
        public void DecryptFile(FileInfo inputFile, FileInfo outputFile) => Decrypt(inputFile, outputFile);
        public void DecryptStream(Stream inputStream, Stream outputStream) => Decrypt(inputStream, outputStream);

        #endregion Decrypt

        #region DecryptAndVerify

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message.
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file</param>
        public void DecryptAndVerify(FileInfo inputFile, FileInfo outputFile) => DecryptAndVerifyAsync(inputFile, outputFile).GetAwaiter().GetResult();

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message.
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public void DecryptAndVerify(Stream inputStream, Stream outputStream) => DecryptAndVerifyAsync(inputStream, outputStream).GetAwaiter().GetResult();

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message.
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        public string DecryptAndVerify(string input) => DecryptAndVerifyAsync(input).GetAwaiter().GetResult();

        public string DecryptArmoredStringAndVerify(string input) => DecryptAndVerify(input);

        public void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile) => DecryptAndVerify(inputFile, outputFile);

        public void DecryptStreamAndVerify(Stream inputStream, Stream outputStream) => DecryptAndVerify(inputStream, outputStream);

        #endregion DecryptAndVerify
    }
}
