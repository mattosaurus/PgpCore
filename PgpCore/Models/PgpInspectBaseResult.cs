using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.Text;

namespace PgpCore.Models
{
    public class PgpInspectBaseResult
    {
        public PgpInspectBaseResult(
            bool isCompressed,
            bool isEncrypted,
            bool isIntegrityProtected,
            bool isSigned,
            SymmetricKeyAlgorithmTag symmetricKeyAlgorithm,
            string fileName,
            DateTime modificationDateTime
            )
        {
            IsCompressed = isCompressed;
            IsEncrypted = isEncrypted;
            IsIntegrityProtected = isIntegrityProtected;
            IsSigned = isSigned;
            SymmetricKeyAlgorithm = symmetricKeyAlgorithm;
            FileName = fileName;
            ModificationDateTime = modificationDateTime;
        }

        public bool IsCompressed { get; }
        public bool IsEncrypted { get; }
        public bool IsIntegrityProtected { get; }
        public bool IsSigned { get; }
        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; }
        public string FileName { get; }
        public DateTime ModificationDateTime { get; }
    }
}
