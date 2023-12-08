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
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null)
                {
                    await Task.Run(() => GenerateKey(publicKeyFileInfo, privateKeyFileInfo, username, password, strength,
                        certainty, armor, emitVersion, keyExpirationInSeconds, signatureExpirationInSeconds,
                        preferredCompressionAlgorithms, preferredHashAlgorithmTags, preferredSymetricKeyAlgorithms));
                }

        public async Task GenerateKeyAsync(
            Stream publicKeyStream,
            Stream privateKeyStream,
            string username = null,
            string password = null,
            int strength = 1024,
            int certainty = 8,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null)
        {
            await Task.Run(() => GenerateKey(publicKeyStream, privateKeyStream, username, password, strength,
                certainty, armor, emitVersion, keyExpirationInSeconds, signatureExpirationInSeconds,
                preferredCompressionAlgorithms, preferredHashAlgorithmTags, preferredSymetricKeyAlgorithms));
        }
    }
}
