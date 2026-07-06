using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace PgpCore.Tests.UnitTests.Interop
{
    /// <summary>
    /// A <see cref="FactAttribute"/> that skips the test at runtime when the gpg executable is not
    /// available on the machine (or is older than the optional minimum version).
    /// </summary>
    public sealed class GpgFactAttribute : FactAttribute
    {
        public GpgFactAttribute(string minimumGpgVersion = null)
        {
            if (GpgRunner.GpgVersion == null)
                Skip = "gpg is not available on this machine";
            else if (minimumGpgVersion != null && GpgRunner.GpgVersion < Version.Parse(minimumGpgVersion))
                Skip = $"test requires gpg >= {minimumGpgVersion} but found {GpgRunner.GpgVersion}";
        }
    }

    /// <summary>
    /// The outcome of a gpg invocation, captured for assertion messages.
    /// </summary>
    public sealed class GpgResult
    {
        public GpgResult(string command, int exitCode, string stdOut, string stdErr)
        {
            Command = command;
            ExitCode = exitCode;
            StdOut = stdOut;
            StdErr = stdErr;
        }

        public string Command { get; }
        public int ExitCode { get; }
        public string StdOut { get; }
        public string StdErr { get; }

        public string Details => $"command [{Command}] exited with {ExitCode}. stdout: {StdOut}. stderr: {StdErr}";
    }

    /// <summary>
    /// Helper for shelling out to GnuPG. Works with both gpg 1.4 (e.g. bundled with Git for Windows)
    /// and gpg 2.x (Linux CI) by only using command forms valid in both and conditionally adding
    /// 2.x-only flags such as <c>--pinentry-mode loopback</c>.
    /// </summary>
    public static class GpgRunner
    {
        private static readonly Lazy<Version> _gpgVersion = new Lazy<Version>(DetectGpgVersion, LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>Detected gpg version, or null when gpg is not available.</summary>
        public static Version GpgVersion => _gpgVersion.Value;

        private static Version DetectGpgVersion()
        {
            try
            {
                int exitCode = RunProcess("gpg", new[] { "--version" }, out string stdOut, out _);
                if (exitCode != 0)
                    return null;

                // First line looks like "gpg (GnuPG) 2.3.6".
                string firstLine = stdOut.Split('\n')[0];
                Match match = Regex.Match(firstLine, @"(\d+)\.(\d+)(?:\.(\d+))?");
                if (!match.Success)
                    return null;

                return new Version(
                    int.Parse(match.Groups[1].Value),
                    int.Parse(match.Groups[2].Value),
                    match.Groups[3].Success ? int.Parse(match.Groups[3].Value) : 0);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Creates a fresh gpg home directory under the system temp path.</summary>
        public static string CreateHomeDir()
        {
            string homeDir = Path.Combine(Path.GetTempPath(), "pgpcore-gpg-" + Guid.NewGuid().ToString("N").Substring(0, 12));
            Directory.CreateDirectory(homeDir);
            return homeDir;
        }

        /// <summary>
        /// Best-effort removal of a gpg home directory. With gpg >= 2.1 the gpg-agent spawned for the
        /// home directory is asked to shut down first so it releases its file handles.
        /// </summary>
        public static void DeleteHomeDir(string homeDir)
        {
            if (homeDir == null || !Directory.Exists(homeDir))
                return;

            if (GpgVersion != null && GpgVersion >= new Version(2, 1))
            {
                try
                {
                    RunProcess("gpgconf", new[] { "--homedir", homeDir, "--kill", "all" }, out _, out _);
                }
                catch
                {
                    // gpgconf missing or failed - fall through to the delete retries below.
                }
            }

            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    Directory.Delete(homeDir, true);
                    return;
                }
                catch (DirectoryNotFoundException)
                {
                    return;
                }
                catch (IOException)
                {
                    Thread.Sleep(200);
                }
                catch (UnauthorizedAccessException)
                {
                    Thread.Sleep(200);
                }
            }
            // Leave the temp directory behind rather than failing the test on cleanup.
        }

        /// <summary>
        /// Runs gpg against the given home directory with <c>--batch --yes --trust-model always</c>
        /// always applied. When a passphrase is supplied it is passed with <c>--passphrase</c>, adding
        /// <c>--pinentry-mode loopback</c> for gpg >= 2.1.
        /// </summary>
        public static GpgResult Run(string homeDir, string passphrase, params string[] arguments)
        {
            List<string> args = new List<string>
            {
                "--homedir", homeDir,
                "--batch",
                "--yes",
                "--trust-model", "always"
            };

            if (passphrase != null)
            {
                if (GpgVersion != null && GpgVersion >= new Version(2, 1))
                {
                    args.Add("--pinentry-mode");
                    args.Add("loopback");
                }

                args.Add("--passphrase");
                args.Add(passphrase);
            }

            args.AddRange(arguments);

            int exitCode = RunProcess("gpg", args, out string stdOut, out string stdErr);
            return new GpgResult("gpg " + string.Join(" ", args), exitCode, stdOut, stdErr);
        }

        private static int RunProcess(string fileName, IReadOnlyList<string> arguments, out string stdOut, out string stdErr)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = fileName;
                foreach (string argument in arguments)
                    process.StartInfo.ArgumentList.Add(argument);
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();

                Task<string> stdOutTask = process.StandardOutput.ReadToEndAsync();
                Task<string> stdErrTask = process.StandardError.ReadToEndAsync();

                if (!process.WaitForExit(120_000))
                {
                    try
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    catch
                    {
                        // Already exited.
                    }

                    throw new TimeoutException($"{fileName} {string.Join(" ", arguments)} did not exit within 120 seconds.");
                }

                stdOut = stdOutTask.GetAwaiter().GetResult();
                stdErr = stdErrTask.GetAwaiter().GetResult();
                return process.ExitCode;
            }
        }
    }

    /// <summary>
    /// Interoperability tests that round-trip data between PgpCore and a real GnuPG installation.
    /// These guard against regressions where PgpCore output cannot be consumed by gpg or vice versa.
    /// Skipped automatically when gpg is not installed.
    /// </summary>
    public class GpgInteropTests : TestBase
    {
        [GpgFact]
        [Trait("Category", "Interop")]
        public void PgpCoreEncrypt_GpgDecrypt_ShouldProduceOriginalContent()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                testFactory.Arrange(KeyType.Generated, FileType.Known);
                EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
                PGP pgp = new PGP(encryptionKeys);

                // Act
                pgp.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

                GpgResult importPublic = GpgRunner.Run(homeDir, null,
                    "--import", testFactory.PublicKeyFileInfo.FullName);
                GpgResult importSecret = GpgRunner.Run(homeDir, testFactory.Password,
                    "--import", testFactory.PrivateKeyFileInfo.FullName);

                string decryptedFilePath = Path.Combine(homeDir, "decrypted.txt");
                GpgResult decrypt = GpgRunner.Run(homeDir, testFactory.Password,
                    "--output", decryptedFilePath,
                    "--decrypt", testFactory.EncryptedContentFileInfo.FullName);

                // Assert
                importPublic.ExitCode.Should().Be(0, "gpg should import the PgpCore public key: {0}", importPublic.Details);
                importSecret.ExitCode.Should().Be(0, "gpg should import the PgpCore private key: {0}", importSecret.Details);
                decrypt.ExitCode.Should().Be(0, "gpg should decrypt the PgpCore encrypted file: {0}", decrypt.Details);
                File.ReadAllText(decryptedFilePath).Should().Be(testFactory.Content);
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
                testFactory.Teardown();
            }
        }

        [GpgFact("2.1")]
        [Trait("Category", "Interop")]
        public void GpgGeneratedKey_PgpCoreRoundTrip_ShouldEncryptSignDecryptAndVerify()
        {
            // Arrange
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                const string email = "pgpcore-interop@example.com";
                const string passphrase = "interop-passphrase";
                const string content = "The quick brown fox jumps over the lazy dog";

                string batchScriptPath = Path.Combine(homeDir, "genkey.batch");
                File.WriteAllText(batchScriptPath, string.Join("\n",
                    "Key-Type: RSA",
                    "Key-Length: 2048",
                    "Subkey-Type: RSA",
                    "Subkey-Length: 2048",
                    "Name-Real: PgpCore Interop Test",
                    $"Name-Email: {email}",
                    "Expire-Date: 0",
                    $"Passphrase: {passphrase}",
                    "%commit",
                    ""));

                GpgResult generateKey = GpgRunner.Run(homeDir, passphrase, "--gen-key", batchScriptPath);
                generateKey.ExitCode.Should().Be(0, "gpg should generate a key pair in batch mode: {0}", generateKey.Details);

                GpgResult exportPublic = GpgRunner.Run(homeDir, null, "--armor", "--export", email);
                GpgResult exportSecret = GpgRunner.Run(homeDir, passphrase, "--armor", "--export-secret-keys", email);
                exportPublic.ExitCode.Should().Be(0, "gpg should export the armored public key: {0}", exportPublic.Details);
                exportSecret.ExitCode.Should().Be(0, "gpg should export the armored private key: {0}", exportSecret.Details);
                exportPublic.StdOut.Should().Contain("BEGIN PGP PUBLIC KEY BLOCK", "gpg should emit an armored public key: {0}", exportPublic.Details);
                exportSecret.StdOut.Should().Contain("BEGIN PGP PRIVATE KEY BLOCK", "gpg should emit an armored private key: {0}", exportSecret.Details);

                // Act - load the gpg generated keys into PgpCore and round-trip.
                EncryptionKeys encryptionKeys = new EncryptionKeys(exportPublic.StdOut, exportSecret.StdOut, passphrase);
                PGP pgp = new PGP(encryptionKeys);

                string encrypted = pgp.EncryptAndSign(content);
                string decrypted = pgp.DecryptAndVerify(encrypted);

                // Assert
                decrypted.Should().Be(content);
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
            }
        }

        [GpgFact]
        [Trait("Category", "Interop")]
        public void PgpCoreSign_GpgVerify_ShouldReportValidSignature()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                testFactory.Arrange(KeyType.Generated, FileType.Known);
                EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
                PGP pgp = new PGP(signingKeys);

                // Act
                pgp.Sign(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

                GpgResult importPublic = GpgRunner.Run(homeDir, null,
                    "--import", testFactory.PublicKeyFileInfo.FullName);
                GpgResult verify = GpgRunner.Run(homeDir, null,
                    "--verify", testFactory.SignedContentFileInfo.FullName);

                // Assert
                importPublic.ExitCode.Should().Be(0, "gpg should import the PgpCore public key: {0}", importPublic.Details);
                verify.ExitCode.Should().Be(0, "gpg should verify the PgpCore signed file: {0}", verify.Details);
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
                testFactory.Teardown();
            }
        }

        [GpgFact]
        [Trait("Category", "Interop")]
        public void PgpCoreClearSignWithConsecutiveNewlines_GpgVerify_ShouldReportValidSignature()
        {
            // Arrange - issue #306: consecutive newlines must not break the clear-sign canonicalization.
            TestFactory testFactory = new TestFactory();
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                testFactory.Arrange(KeyType.Generated, FileType.Known);
                EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
                PGP pgp = new PGP(signingKeys);

                string contentFilePath = Path.Combine(homeDir, "content.txt");
                File.WriteAllText(contentFilePath, "foo\n\nbar\n\n");
                string clearSignedFilePath = Path.Combine(homeDir, "clearsigned.asc");

                // Act
                pgp.ClearSign(new FileInfo(contentFilePath), new FileInfo(clearSignedFilePath));

                GpgResult importPublic = GpgRunner.Run(homeDir, null,
                    "--import", testFactory.PublicKeyFileInfo.FullName);
                GpgResult verify = GpgRunner.Run(homeDir, null,
                    "--verify", clearSignedFilePath);

                // Assert
                importPublic.ExitCode.Should().Be(0, "gpg should import the PgpCore public key: {0}", importPublic.Details);
                verify.ExitCode.Should().Be(0, "gpg should verify the PgpCore clear-signed file: {0}", verify.Details);
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
                testFactory.Teardown();
            }
        }

        [GpgFact]
        [Trait("Category", "Interop")]
        public void PgpCoreGeneratedKey_GpgImport_ShouldSucceed()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            string homeDir = GpgRunner.CreateHomeDir();

            try
            {
                testFactory.Arrange(KeyType.Generated);

                // Act
                GpgResult importPublic = GpgRunner.Run(homeDir, null,
                    "--import", testFactory.PublicKeyFileInfo.FullName);
                GpgResult importSecret = GpgRunner.Run(homeDir, testFactory.Password,
                    "--import", testFactory.PrivateKeyFileInfo.FullName);
                GpgResult listKeys = GpgRunner.Run(homeDir, null, "--list-keys");

                // Assert
                importPublic.ExitCode.Should().Be(0, "gpg should import the PgpCore generated public key: {0}", importPublic.Details);
                importSecret.ExitCode.Should().Be(0, "gpg should import the PgpCore generated private key: {0}", importSecret.Details);
                listKeys.ExitCode.Should().Be(0, "gpg should list the imported keys: {0}", listKeys.Details);
                listKeys.StdOut.Should().Contain(testFactory.UserName, "the imported key should carry the PgpCore user id: {0}", listKeys.Details);
            }
            finally
            {
                GpgRunner.DeleteHomeDir(homeDir);
                testFactory.Teardown();
            }
        }
    }
}
