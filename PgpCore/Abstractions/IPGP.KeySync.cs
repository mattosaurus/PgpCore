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
            string username = null,
            string password = null,
            int strength = 3072,
            int certainty = 24,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymmetricKeyAlgorithms = null);

        void GenerateKey(
            Stream publicKeyStream,
            Stream privateKeyStream,
            string username = null,
            string password = null,
            int strength = 3072,
            int certainty = 24,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0,
            CompressionAlgorithmTag[] preferredCompressionAlgorithms = null,
            HashAlgorithmTag[] preferredHashAlgorithmTags = null,
            SymmetricKeyAlgorithmTag[] preferredSymmetricKeyAlgorithms = null);
    }
}
