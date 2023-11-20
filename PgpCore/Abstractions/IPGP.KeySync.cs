using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PgpCore.Abstractions
{
    public interface IKeySync
    {
        void GenerateKey(
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

        void GenerateKey(
            Stream publicKeyStream,
            Stream privateKeyStream,
            string username,
            string password,
            int strength,
            int certainty,
            bool armor,
            bool emitVersion,
            long keyExpirationInSeconds,
            long signatureExpirationInSeconds,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms,
            HashAlgorithmTag[] preferredHashAlgorithmTags,
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms);
    }
}
