using Org.BouncyCastle.Bcpg;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IKeyAsync
    {
        Task GenerateKeyAsync(
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
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null);

        Task GenerateKeyAsync(
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
            SymmetricKeyAlgorithmTag[] preferredSymetricKeyAlgorithms = null);
    }
}
