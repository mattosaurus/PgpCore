using Org.BouncyCastle.Bcpg;
using PgpCore.Abstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP : IKeyAsync
    {
        public async Task GenerateKeyAsync(
            FileInfo publicKeyFileInfo,
            FileInfo privateKeyFileInfo,
            string username = null,
            string password = null,
            int strength = 1024,
            int certainty = 8,
            bool emitVersion = true,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null)
                {
                    await Task.Run(() => GenerateKey(publicKeyFileInfo, privateKeyFileInfo, username, password, strength,
                        certainty, emitVersion, preferredCompressionAlgorithms, preferredHashAlgorithmTags, preferredSymetricKeyAlgorithms));
                }
    }
}
