using System;
using System.Collections.Generic;

namespace PgpCore.Models
{
    public class PGPInspectResult
    {
        public PGPInspectResult(
            bool isArmored,
            bool isCompressed,
            bool isEncrypted,
            bool isIntegrityProtected,
            bool isSigned,
            Dictionary<string, string> messageHeaders,
            string fileName,
            DateTime modificationDateTime
            )
        {
            IsArmored = isArmored;
            IsCompressed = isCompressed;
            IsEncrypted = isEncrypted;
            IsIntegrityProtected = isIntegrityProtected;
            IsSigned = isSigned;
            MessageHeaders = messageHeaders;
            FileName = fileName;
            ModificationDateTime = modificationDateTime;
        }

        public bool IsArmored { get; }
        public bool IsCompressed { get; }
        public bool IsEncrypted { get; }
        public bool IsIntegrityProtected { get; }
        public bool IsSigned { get; }
        public Dictionary<string, string> MessageHeaders { get; }
        public string FileName { get; }
        public string Version => MessageHeaders.ContainsKey("Version") ? MessageHeaders["Version"] : null;
        public string Comment => MessageHeaders.ContainsKey("Comment") ? MessageHeaders["Comment"] : null;
        public DateTime ModificationDateTime { get; }
    }
}
