using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.Zlib;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PgpCore
{
    public partial class PGP : IInspectSync
    {
        /// <summary>
        /// Inspect an arbitary PGP message returning information about the message
        /// </summary>
        /// <param name="inputStream">The input stream containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public PGPInspectResult Inspect(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            bool isArmored = IsArmored(inputStream);
            bool isSigned = false;
            bool isCompressed = false;
            bool isEncrypted = false;
            bool isIntegrityProtected = false;
            Dictionary<string, string> messageHeaders = GetMessageHeaders(inputStream);
            string fileName = null;
            DateTime modificationDateTime = DateTime.MinValue;

            PgpLiteralData pgpLiteralData = null;

            inputStream.Seek(0, SeekOrigin.Begin);
            PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            PgpObject pgpObject = pgpObjectFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            if (pgpObject is PgpEncryptedDataList dataList)
            {
                isEncrypted = true;
                enc = dataList;
            }
            else if (pgpObject is PgpCompressedData compressedData)
            {
                isCompressed = true;
                message = compressedData;
            }
            else if (pgpObject is PgpLiteralData literalData)
                message = literalData;
            else if (pgpObject is PgpOnePassSignatureList || pgpObject is PgpSignatureList)
            {
                isSigned = true;
                message = pgpObjectFactory.NextPgpObject();
            }
            else
                enc = (PgpEncryptedDataList)pgpObjectFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                if (enc != null)
                {
                    isEncrypted = true;
                    foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in enc.GetEncryptedDataObjects())
                    {
                        isIntegrityProtected = publicKeyEncryptedData.IsIntegrityProtected();
                        privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

                        if (privateKey != null)
                        {
                            pbe = publicKeyEncryptedData;
                            break;
                        }
                    }

                    if (privateKey == null)
                        throw new ArgumentException("Secret key for message not found.");

                    Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    message = plainFact.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        isSigned = true;
                        message = plainFact.NextPgpObject();
                    }
                }

                if (message is PgpCompressedData pgpCompressedData)
                {
                    isCompressed = true;
                    Stream compDataIn = pgpCompressedData.GetDataStream().DisposeWith(disposables);
                    PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
                    message = objectFactory.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        isSigned = true;
                        message = objectFactory.NextPgpObject();
                        pgpLiteralData = (PgpLiteralData)message;
                    }
                    else
                    {
                        pgpLiteralData = (PgpLiteralData)message;
                    }
                }
                else if (message is PgpLiteralData literalData)
                {
                    pgpLiteralData = literalData;
                }
                else
                    throw new PgpException("Message is not a simple encrypted file.");
            }

            fileName = pgpLiteralData.FileName;
            modificationDateTime = pgpLiteralData.ModificationTime;

            return new PGPInspectResult(
                isArmored,
                isCompressed,
                isEncrypted,
                isIntegrityProtected,
                isSigned,
                messageHeaders,
                fileName,
                modificationDateTime
                );
        }

        /// <summary>
        /// Inspect an arbitary PGP message returning information about the message
        /// </summary>
        /// <param name="inputFile">The input file containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public PGPInspectResult Inspect(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (FileStream inputStream = inputFile.OpenRead())
                return Inspect(inputStream);
        }

        /// <summary>
        /// Inspect an arbitary PGP message returning information about the message
        /// </summary>
        /// <param name="input">The input string containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public PGPInspectResult Inspect(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input");

            using (Stream inputStream = input.GetStream())
            {
                return Inspect(inputStream);
            }
        }

        private Dictionary<string, string> GetMessageHeaders(Stream inputStream)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();

            using (StreamReader reader = new StreamReader(inputStream))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
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
            }

            return headers;
        }

        private bool IsArmored(byte[] data)
        {
            if (data[0] == 0x2D && data[1] == 0x2D && data[2] == 0x2D && data[3] == 0x2D && data[4] == 0x2D && data[5] == 0x42 && data[6] == 0x45 && data[7] == 0x47 && data[8] == 0x49 && data[9] == 0x4E && data[10] == 0x20 && data[11] == 0x50 && data[12] == 0x47 && data[13] == 0x50 && data[14] == 0x20 && data[15] == 0x4D && data[16] == 0x45 && data[17] == 0x53 && data[18] == 0x53 && data[19] == 0x41 && data[20] == 0x47 && data[21] == 0x45 && data[22] == 0x2D && data[23] == 0x2D && data[24] == 0x2D && data[25] == 0x2D)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private bool IsArmored(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            byte[] headerBytes = new byte[26];
            stream.Read(headerBytes, 0, 26);
            return IsArmored(headerBytes);
        }
    }
}
