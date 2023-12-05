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

namespace PgpCore
{
    public partial class PGP : IInspectSync
    {
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

        private PGPInspectResult GetPgpDetails(Stream inputStream)
        {
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

        private Dictionary<string, string> GetMessageHeaders(byte[] data)
        {
            Dictionary<string, string> messageHeaders = new Dictionary<string, string>();
            if (data[0] == 0x85 && data[1] == 0x1 && data[2] == 0x1)
            {
                int fileNameLength = (data[3] << 8) | data[4];
                int headerLength = (data[5 + fileNameLength] << 8) | data[6 + fileNameLength];
                byte[] headerBytes = new byte[headerLength];
                Array.Copy(data, 7 + fileNameLength, headerBytes, 0, headerLength);
                string headerString = Encoding.UTF8.GetString(headerBytes);
                string[] headerLines = headerString.Split('\n');
                foreach (string headerLine in headerLines)
                {
                    string[] header = headerLine.Split(':');
                    if (header.Length == 2)
                    {
                        messageHeaders.Add(header[0].Trim(), header[1].Trim());
                    }
                }
            }
            else if (data[0] == 0x1F && data[1] == 0x8B)
            {
                int fileNameLength = (data[3] << 8) | data[4];
                int headerLength = (data[5 + fileNameLength] << 8) | data[6 + fileNameLength];
                byte[] headerBytes = new byte[headerLength];
                Array.Copy(data, 7 + fileNameLength, headerBytes, 0, headerLength);
                string headerString = Encoding.UTF8.GetString(headerBytes);
                string[] headerLines = headerString.Split('\n');
                foreach (string headerLine in headerLines)
                {
                    string[] header = headerLine.Split(':');
                    if (header.Length == 2)
                    {
                        messageHeaders.Add(header[0].Trim(), header[1].Trim());
                    }
                }
            }
            else if (data[0] == 0x3 && data[1] == 0x1 && data[2] == 0x8 && data[3] == 0x6 && data[4] == 0x0 && data[5] == 0x0 && data[6] == 0x0 && data[7] == 0x0 && data[8] == 0x0)
            {
                int fileNameLength = (data[9]);
                int headerLength = (data[10 + fileNameLength] << 8) | data[11 + fileNameLength];
                byte[] headerBytes = new byte[headerLength];
                Array.Copy(data, 12 + fileNameLength, headerBytes, 0, headerLength);
                string headerString = Encoding.UTF8.GetString(headerBytes);
                string[] headerLines = headerString.Split('\n');
                foreach (string headerLine in headerLines)
                {
                    string[] header = headerLine.Split(':');
                    if (header.Length == 2)
                    {
                        messageHeaders.Add(header[0].Trim(), header[1].Trim());
                    }
                }
            }
            else if (data[0] == 0x6 && data[1] == 0x9 && data[2] == 0x2A && data[3] == 0x86 && data[4] == 0x48 && data[5] == 0x86 && data[6] == 0xF7 && data[7] == 0xD && data[8] == 0x1 && data[9] == 0x7 && data[10] == 0x1 && data[11] == 0xA)
            {
                int fileNameLength = (data[12]);
                int headerLength = (data[13 + fileNameLength] << 8) | data[14 + fileNameLength];
                byte[] headerBytes = new byte[headerLength];
                Array.Copy(data, 15 + fileNameLength, headerBytes, 0, headerLength);
                string headerString = Encoding.UTF8.GetString(headerBytes);
                string[] headerLines = headerString.Split('\n');
                foreach (string headerLine in headerLines)
                {
                    string[] header = headerLine.Split(':');
                    if (header.Length == 2)
                    {
                        messageHeaders.Add(header[0].Trim(), header[1].Trim());
                    }
                }
            }

            return messageHeaders;
        }

        private Dictionary<string, string> GetMessageHeaders(Stream inputStream)
        {
            // Get the bytes from the inputStream that contain the headers
            inputStream.Seek(0, SeekOrigin.Begin);
            byte[] headerLengthBytes = new byte[2];
            inputStream.Read(headerLengthBytes, 0, 2);
            int headerLength = (headerLengthBytes[0] << 8) | headerLengthBytes[1];
            byte[] headerBytes = new byte[headerLength];
            inputStream.Read(headerBytes, 0, headerLength);

            return GetMessageHeaders(headerBytes);
        }

        // Method to inspect an arbitary PGP message returning information about the message
        public PGPInspectResult Inspect(Stream inputStream)
        {
            return GetPgpDetails(inputStream);
        }
    }
}
