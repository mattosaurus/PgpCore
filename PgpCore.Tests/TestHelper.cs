using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Tests
{
    internal static class TestHelper
    {
        internal static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }
            throw new ArgumentException("No encryption key found in public key ring.");
        }

        internal static IEnumerable<T> GetEnumValues<T>() where T : struct, IConvertible
        {
            foreach (T enumValue in Enum.GetValues(typeof(T)))
            {
                yield return enumValue;
            }
        }

        internal static IEnumerable<object[]> GetAllCombinations()
        {
            foreach (CompressionAlgorithmTag compressionAlgorithmTag in GetEnumValues<CompressionAlgorithmTag>())
                foreach (HashAlgorithmTag hashAlgorithmTag in GetEnumValues<HashAlgorithmTag>())
                    foreach (SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag in GetEnumValues<SymmetricKeyAlgorithmTag>())
                    {
                        yield return new object[] { compressionAlgorithmTag, hashAlgorithmTag, symmetricKeyAlgorithmTag };
                    }
        }
    }
}
