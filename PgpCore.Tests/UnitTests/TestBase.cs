using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore.Tests.UnitTests
{
    public class TestBase
    {
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
    }
}
