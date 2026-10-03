using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Safety
{
    [CollectionDefinition("Cleartext allocation", DisableParallelization = true)]
    public class ClearTextAllocationCollection { }

    [Collection("Cleartext allocation")]
    public class ClearTextMemoryTests
    {
        [Fact]
        public async Task LongCleartextLine_VerifiesWithoutAllocatingMemoryProportionalToItsLength()
        {
            using var publicKey = new MemoryStream();
            using var privateKey = new MemoryStream();
            new PGP().GenerateKey(publicKey, privateKey, strength: 1024, certainty: 8);
            publicKey.Position = privateKey.Position = 0;
            var keys = new EncryptionKeys(publicKey, privateKey, "");
            var signature = new PgpSignatureGenerator(keys.SigningSecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            signature.InitSign(PgpSignature.CanonicalTextDocument, keys.SigningPrivateKey);
            using var input = new MemoryStream();
            using (var armored = new ArmoredOutputStream(input))
            {
                armored.BeginClearText(HashAlgorithmTag.Sha256);
                byte[] chunk = Enumerable.Repeat((byte)'a', 16384).ToArray();
                for (int i = 0; i < 1024; i++)
                {
                    armored.Write(chunk);
                    signature.Update(chunk);
                }
                // Trailing whitespace crosses the spool's buffer boundary. Empty lines
                // remain signed, while the separator before the armor is excluded.
                armored.Write(Enumerable.Repeat((byte)' ', 20000).ToArray());
                byte[] separator = Encoding.ASCII.GetBytes("\r\n");
                armored.Write(separator);
                signature.Update(separator);
                armored.Write(separator);
                signature.Update(separator);
                byte[] tail = Encoding.ASCII.GetBytes("tail");
                armored.Write(tail);
                signature.Update(tail);
                armored.Write(separator);
                armored.EndClearText();
                signature.Generate().Encode(armored);
            }
            input.Position = 0;
            long before = GC.GetTotalAllocatedBytes(true);
            Assert.True(await new PGP(keys).VerifyClearAsync(input));
            long allocated = GC.GetTotalAllocatedBytes(true) - before;
            Assert.True(allocated < 8 * 1024 * 1024, $"Verification allocated {allocated:N0} bytes for a 16 MiB line.");
        }
    }
}
