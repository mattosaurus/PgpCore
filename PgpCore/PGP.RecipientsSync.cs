using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PgpCore
{
    public partial class PGP : IRecipientsSync
    {
        #region GetFileRecipients

        /// <summary>
        /// PGP get a recipients keys id of an encrypted file.
        /// </summary>
        /// <param name="inputFilePath">PGP encrypted data file path</param>
        /// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
        public IEnumerable<long> GetFileRecipients(FileInfo inputFileInfo)
        {
            if (inputFileInfo == null)
                throw new ArgumentException("InputFileInfo");

            if (!inputFileInfo.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFileInfo.FullName}] not found.");

            using (Stream inputStream = File.OpenRead(inputFileInfo.FullName))
                return GetStreamRecipients(inputStream);
        }

        #endregion GetFileRecipients

        #region GetStreamRecipients

        /// <summary>
        /// PGP get a recipients keys id of an encrypted stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
        public IEnumerable<long> GetStreamRecipients(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc;

            if (obj is PgpEncryptedDataList list)
                enc = list;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc is null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            // Return keys id
            return enc.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().Select(k => k.KeyId);
        }

        #endregion GetStreamRecipients

        #region GetArmoredStringRecipients

        /// <summary>
        /// PGP get a recipients keys id of an encrypted file.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        /// <returns>Enumerable of public key ids. Value "0" means that the recipient is hidden.</returns>
        public IEnumerable<long> GetArmoredStringRecipients(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input");

            using (Stream inputStream = input.GetStream())
                return GetStreamRecipients(inputStream);
        }

        #endregion GetArmoredStringRecipients
    }
}
