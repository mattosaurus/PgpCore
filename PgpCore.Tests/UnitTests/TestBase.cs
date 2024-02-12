using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Tests.UnitTests
{
    public abstract class TestBase
    {
#if NETFRAMEWORK
        public const string VERSION = "BouncyCastle.NET Cryptography (net461) v2.1.1+851feee009";
#else
        public const string VERSION = "BouncyCastle.NET Cryptography (net6.0) v2.1.1+851feee009";
#endif
        public const string DEFAULTNAME = "name";
        public const string TESTNAME = "Test Name";
        public const string TESTHEADERKEY = "Test Header";
        public const string TESTHEADERVALUE = "Test Value";

        public static IEnumerable<object[]> GetCompressionAlgorithimTags()
        {
            foreach (CompressionAlgorithmTag compressionAlgorithmTag in TestHelper.GetEnumValues<CompressionAlgorithmTag>())
            {
                yield return new object[] { compressionAlgorithmTag };
            }
        }

        public static IEnumerable<object[]> GetHashAlgorithimTags()
        {
            foreach (HashAlgorithmTag hashAlgorithmTag in TestHelper.GetEnumValues<HashAlgorithmTag>())
            {
                yield return new object[] { hashAlgorithmTag };
            }
        }

        public static IEnumerable<object[]> GetSymmetricAlgorithimTags()
        {
            foreach (SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag in TestHelper.GetEnumValues<SymmetricKeyAlgorithmTag>())
            {
                // Exclude as null is not for encryption and safer is not supported.
                if (symmetricKeyAlgorithmTag == SymmetricKeyAlgorithmTag.Null || symmetricKeyAlgorithmTag == SymmetricKeyAlgorithmTag.Safer)
                    continue;

                yield return new object[] { symmetricKeyAlgorithmTag };
            }
        }

        public static PgpPublicKey ReadPublicKey(Stream inputStream)
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

        public static IEnumerable<T> GetEnumValues<T>() where T : struct, IConvertible
        {
            foreach (T enumValue in Enum.GetValues(typeof(T)))
            {
                yield return enumValue;
            }
        }
    }
}
