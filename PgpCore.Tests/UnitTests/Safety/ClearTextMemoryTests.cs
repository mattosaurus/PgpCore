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
        public async Task ManyShortCleartextLines_PreserveLineBoundariesAndVerify()
        {
            var pgp = new PGP(new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1));
            string text = string.Concat(Enumerable.Repeat("short line\n", 10000));
            string signed = await pgp.ClearSignAsync(text);
            Assert.True(await pgp.VerifyClearAsync(signed));
        }

        [Fact]
        public async Task ClearSigning_PreservesTrailingUnicodeWhitespaceInTheSignature()
        {
            var pgp = new PGP(new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1));
            string signed = await pgp.ClearSignAsync("Unicode whitespace\u00A0\u2003\nsecond line");
            Assert.True(await pgp.VerifyClearAsync(signed));
        }

        [Fact]
        public async Task ClearVerification_RejectsAnUnmatchedUnhashedIssuerId()
        {
            var keys = new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1);
            var generator = new PgpSignatureGenerator(keys.SigningSecretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.CanonicalTextDocument, keys.SigningPrivateKey);
            var unhashed = new PgpSignatureSubpacketGenerator();
            unhashed.SetIssuerKeyID(false, keys.SigningSecretKey.KeyId ^ 1);
            generator.SetUnhashedSubpackets(unhashed.Generate());
            byte[] payload = Encoding.UTF8.GetBytes("issuer mismatch");
            generator.Update(payload);
            using var input = new MemoryStream();
            using (var armor = new ArmoredOutputStream(input))
            {
                armor.BeginClearText(HashAlgorithmTag.Sha256);
                armor.Write(payload);
                armor.Write(Encoding.ASCII.GetBytes("\r\n"));
                armor.EndClearText();
                generator.Generate().Encode(armor);
            }
            input.Position = 0;
            Assert.False(await new PGP(keys).VerifyClearAsync(input));
        }

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
