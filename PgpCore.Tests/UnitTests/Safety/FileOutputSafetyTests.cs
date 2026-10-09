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
    public sealed class UnixFactAttribute : FactAttribute
    {
        public UnixFactAttribute() { if (OperatingSystem.IsWindows()) Skip = "Unix permission contract"; }
    }

    public sealed class FileOutputSafetyTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "PgpCore-safety-" + Guid.NewGuid().ToString("N"));
        private readonly PGP _pgp;

        public FileOutputSafetyTests()
        {
            Directory.CreateDirectory(_root);
            var publicKey = File("public.asc");
            var privateKey = File("private.asc");
            new PGP().GenerateKey(publicKey, privateKey, "safety@example.test", "", strength: 1024, certainty: 8);
            _pgp = new PGP(new EncryptionKeys(publicKey, privateKey, ""));
        }

        private FileInfo File(string name) => new FileInfo(Path.Combine(_root, name));
        public void Dispose() => Directory.Delete(_root, true);

        [UnixFact]
        [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
        public void GeneratedPrivateKey_IsOwnerOnlyWhilePublicOutputUsesCreationDefaults()
        {
            var expected = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            var defaultFile = File("creation-default.txt");
            System.IO.File.WriteAllText(defaultFile.FullName, "default mode");
            Assert.Equal(System.IO.File.GetUnixFileMode(defaultFile.FullName), System.IO.File.GetUnixFileMode(File("public.asc").FullName));
            Assert.Equal(expected, System.IO.File.GetUnixFileMode(File("private.asc").FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [UnixFact]
        [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
        public async Task ReplacingOutput_PreservesDestinationPermissions()
        {
            var input = File("input.txt");
            var output = File("shared.pgp");
            System.IO.File.WriteAllText(input.FullName, "shared drop-folder payload");
            System.IO.File.WriteAllText(output.FullName, "existing");
            var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;
            System.IO.File.SetUnixFileMode(output.FullName, mode);
            await _pgp.EncryptAsync(input, output);
            Assert.Equal(mode, System.IO.File.GetUnixFileMode(output.FullName));
            Assert.Equal("shared drop-folder payload", await _pgp.DecryptAsync(System.IO.File.ReadAllText(output.FullName)));
        }

        [UnixFact]
        [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
        public void ReplacingSecretKey_RestrictsPreviouslySharedPermissions()
        {
            System.IO.File.SetUnixFileMode(File("private.asc").FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            new PGP().GenerateKey(File("public.asc"), File("private.asc"), strength: 1024, certainty: 8);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, System.IO.File.GetUnixFileMode(File("private.asc").FullName));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task Decrypt_ReplacesExistingLongerOutputExactly(bool verify)
        {
            var input = File("input.pgp");
            var output = File("output.txt");
            System.IO.File.WriteAllText(input.FullName, verify ? await _pgp.EncryptAndSignAsync("short") : await _pgp.EncryptAsync("short"));
            System.IO.File.WriteAllText(output.FullName, "existing longer content must not survive");
            if (verify)
                await _pgp.DecryptAndVerifyAsync(input, output);
            else
                await _pgp.DecryptAsync(input, output);
            Assert.Equal("short", System.IO.File.ReadAllText(output.FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [Theory]
        [InlineData(CompressionAlgorithmTag.Zip, false)]
        [InlineData(CompressionAlgorithmTag.Zip, true)]
        [InlineData(CompressionAlgorithmTag.Uncompressed, false)]
        [InlineData(CompressionAlgorithmTag.Uncompressed, true)]
        public async Task FailedIntegrity_PreservesExistingDestinationAndDoesNotPublishNewPlaintext(CompressionAlgorithmTag compression, bool existing)
        {
            _pgp.CompressionAlgorithm = compression;
            using var clear = new MemoryStream(Encoding.UTF8.GetBytes("unauthenticated plaintext"));
            using var encrypted = new MemoryStream();
            await _pgp.EncryptAsync(clear, encrypted, armor: false);
            byte[] bytes = encrypted.ToArray();
            bytes[bytes.Length - 3] ^= 1;
            var input = File("corrupt.pgp");
            var output = File("output.txt");
            System.IO.File.WriteAllBytes(input.FullName, bytes);
            if (existing)
                System.IO.File.WriteAllText(output.FullName, "keep original");
            await Assert.ThrowsAsync<MessageIntegrityException>(() => _pgp.DecryptAsync(input, output));
            if (existing)
                Assert.Equal("keep original", System.IO.File.ReadAllText(output.FullName));
            else
                Assert.False(System.IO.File.Exists(output.FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task InvalidSignature_DoesNotCommitExtractedOutput(bool clearSign)
        {
            string signed = clearSign ? await _pgp.ClearSignAsync("original") : await _pgp.SignAsync("original");
            if (clearSign)
                signed = signed.Replace("original", "modified");
            else
            {
                _pgp.CompressionAlgorithm = CompressionAlgorithmTag.Uncompressed;
                using var data = new MemoryStream(Encoding.UTF8.GetBytes("original"));
                using var outputBytes = new MemoryStream();
                await _pgp.SignAsync(data, outputBytes, armor: false);
                byte[] bytes = outputBytes.ToArray();
                byte[] needle = Encoding.UTF8.GetBytes("original");
                int offset = Enumerable.Range(0, bytes.Length - needle.Length).First(i => bytes.Skip(i).Take(needle.Length).SequenceEqual(needle));
                bytes[offset] ^= 1;
                System.IO.File.WriteAllBytes(File("signed.pgp").FullName, bytes);
            }
            var input = File("signed.pgp");
            var output = File("result.txt");
            if (clearSign)
                System.IO.File.WriteAllText(input.FullName, signed);
            System.IO.File.WriteAllText(output.FullName, "preserve");
            Assert.False(clearSign ? await _pgp.VerifyClearAsync(input, output) : await _pgp.VerifyAsync(input, output));
            Assert.Equal("preserve", System.IO.File.ReadAllText(output.FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [Fact]
        public void FailedKeyGeneration_PreservesBothExistingFiles()
        {
            var publicKey = File("public.asc");
            var privateKey = File("private.asc");
            byte[] originalPublic = System.IO.File.ReadAllBytes(publicKey.FullName);
            byte[] originalPrivate = System.IO.File.ReadAllBytes(privateKey.FullName);
            Assert.Throws<NotSupportedException>(() => new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.ECDH }
                .GenerateKey(publicKey, privateKey));
            Assert.Equal(originalPublic, System.IO.File.ReadAllBytes(publicKey.FullName));
            Assert.Equal(originalPrivate, System.IO.File.ReadAllBytes(privateKey.FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void SecondKeyCommitFailure_RestoresPublicDestination(bool existing)
        {
            var publicFile = File("rollback-public.asc");
            var privateDirectory = File("private-directory");
            Directory.CreateDirectory(privateDirectory.FullName);
            if (existing) System.IO.File.WriteAllText(publicFile.FullName, "original");
            Assert.ThrowsAny<IOException>(() => new PGP().GenerateKey(publicFile, privateDirectory, strength: 1024, certainty: 8));
            if (existing) Assert.Equal("original", System.IO.File.ReadAllText(publicFile.FullName));
            else Assert.False(System.IO.File.Exists(publicFile.FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void PublicExport_RejectsNonCertificatesAndFingerprintMismatch(bool secretKey)
        {
            var destination = File("download.asc");
            System.IO.File.WriteAllText(destination.FullName, "preserve");
            using var input = secretKey ? System.IO.File.OpenRead(File("private.asc").FullName)
                : new MemoryStream(Encoding.UTF8.GetBytes("<html>server error</html>")) as Stream;
            Assert.Throws<InvalidKeyMaterialException>(() => PGP.ExportPublicKeys(input, destination));
            Assert.Equal("preserve", System.IO.File.ReadAllText(destination.FullName));
            using var publicInput = System.IO.File.OpenRead(File("public.asc").FullName);
            Assert.Throws<InvalidKeyMaterialException>(() => PGP.ExportPublicKeys(publicInput, destination, new string('0', 40)));
            Assert.Equal("preserve", System.IO.File.ReadAllText(destination.FullName));
            Assert.Empty(Directory.GetFileSystemEntries(_root, ".pgpcore-*"));
        }

        [Fact]
        public void PublicExport_MatchesFullFingerprintAndRetainsStreamOwnership()
        {
            using var input = System.IO.File.OpenRead(File("public.asc").FullName);
            string fingerprint = PGP.InspectKeys(input)[0].Fingerprint;
            input.Position = 0;
            using var output = new MemoryStream();
            PGP.ExportPublicKeys(input, output, fingerprint);
            Assert.True(input.CanRead);
            Assert.True(output.CanWrite);
            output.Position = 0;
            Assert.Equal(fingerprint, PGP.InspectKeys(output)[0].Fingerprint);
        }

        [Theory]
        [InlineData("public.asc")]
        [InlineData("PUBLIC.asc")]
        public void KeyGeneration_RejectsSameDestination(string privateName)
        {
            var key = File("public.asc");
            byte[] original = System.IO.File.ReadAllBytes(key.FullName);
            Assert.Throws<ArgumentException>(() => new PGP().GenerateKey(key, File(privateName)));
            Assert.Equal(original, System.IO.File.ReadAllBytes(key.FullName));
        }

        [Theory]
        [InlineData(CompressionAlgorithmTag.Uncompressed)]
        [InlineData(CompressionAlgorithmTag.Zip)]
        [InlineData(CompressionAlgorithmTag.BZip2)]
        public async Task Signing_HonorsCompressionAndLeavesBorrowedStreamsOpen(CompressionAlgorithmTag compression)
        {
            _pgp.CompressionAlgorithm = compression;
            using var input = new MemoryStream(Encoding.UTF8.GetBytes("content"));
            using var output = new MemoryStream();
            await _pgp.SignAsync(input, output, armor: false);
            Assert.True(input.CanRead);
            Assert.True(output.CanWrite);
            var packet = new PgpObjectFactory(new MemoryStream(output.ToArray())).NextPgpObject();
            if (compression == CompressionAlgorithmTag.Uncompressed)
                Assert.IsType<PgpOnePassSignatureList>(packet);
            else
                Assert.Equal(compression, Assert.IsType<PgpCompressedData>(packet).Algorithm);
            output.Position = 0;
            Assert.True(await _pgp.VerifyAsync(output));
        }

        [Theory]
        [InlineData("encrypt")]
        [InlineData("encrypt-sign")]
        [InlineData("sign")]
        [InlineData("clear-sign")]
        [InlineData("detached")]
        [InlineData("decrypt")]
        [InlineData("decrypt-verify")]
        [InlineData("verify")]
        [InlineData("verify-clear")]
        public async Task StreamOperations_RetainCallerOwnership(string operation)
        {
            string payload = operation == "decrypt" ? await _pgp.EncryptAsync("payload")
                : operation == "decrypt-verify" ? await _pgp.EncryptAndSignAsync("payload")
                : operation == "verify" ? await _pgp.SignAsync("payload")
                : operation == "verify-clear" ? await _pgp.ClearSignAsync("payload") : "payload";
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(payload));
            using var output = new MemoryStream();
            switch (operation)
            {
                case "encrypt": await _pgp.EncryptAsync(input, output); break;
                case "encrypt-sign": await _pgp.EncryptAndSignAsync(input, output); break;
                case "sign": await _pgp.SignAsync(input, output); break;
                case "clear-sign": await _pgp.ClearSignAsync(input, output); break;
                case "detached": await _pgp.SignDetachedAsync(input, output); break;
                case "decrypt": await _pgp.DecryptAsync(input, output); break;
                case "decrypt-verify": await _pgp.DecryptAndVerifyAsync(input, output); break;
                case "verify": Assert.True(await _pgp.VerifyAsync(input, output)); break;
                case "verify-clear": Assert.True(await _pgp.VerifyClearAsync(input, output)); break;
            }
            Assert.True(input.CanRead);
            Assert.True(output.CanWrite);
        }
    }
}
