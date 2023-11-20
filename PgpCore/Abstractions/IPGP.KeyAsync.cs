using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IKeyAsync
    {
        Task GenerateKeyAsync(
            FileInfo publicKeyFileInfo,
            FileInfo privateKeyFileInfo,
            string username,
            string password,
            int strength,
            int certainty,
            bool emitVersion,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms,
            HashAlgorithmTag[] preferredHashAlgorithmTags,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms);
    }
}
