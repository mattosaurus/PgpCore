using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Safety
{
    public class ConcatenatedMessageSafetyTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task TruncatedSecondMessage_DoesNotCommitOnlyTheFirstPayload(bool verify)
        {
            var keys = new EncryptionKeys(Constants.PUBLICKEY1, Constants.PRIVATEKEY1, Constants.PASSWORD1);
            var pgp = new PGP(keys);
            using var first = new MemoryStream(Encoding.UTF8.GetBytes("first chunk"));
            using var encrypted = new MemoryStream();
            if (verify) await pgp.EncryptAndSignAsync(first, encrypted, armor: false);
            else await pgp.EncryptAsync(first, encrypted, armor: false);
            // A partially transferred second recipient packet (tag 1) must never be
            // mistaken for harmless trailing content after a complete first chunk.
            encrypted.Write(new byte[] { 0xC1, 0x8C, 3, 0, 0 });
            string root = Path.Combine(Path.GetTempPath(), "pgpcore-concat-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try
            {
                var source = new FileInfo(Path.Combine(root, "chunks.pgp"));
                var destination = new FileInfo(Path.Combine(root, "output.txt"));
                await File.WriteAllBytesAsync(source.FullName, encrypted.ToArray());
                await File.WriteAllTextAsync(destination.FullName, "preserve existing destination");
                await Assert.ThrowsAsync<NotEncryptedDataException>(async () =>
                {
                    if (verify) await pgp.DecryptAndVerifyAsync(source, destination);
                    else await pgp.DecryptAsync(source, destination);
                });
                Assert.Equal("preserve existing destination", await File.ReadAllTextAsync(destination.FullName));
                Assert.Equal(2, Directory.GetFiles(root).Length);
            }
            finally { Directory.Delete(root, true); }
        }
    }
}
