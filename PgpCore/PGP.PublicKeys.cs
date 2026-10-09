using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Helpers;
using System;
using System.IO;
using System.Linq;

namespace PgpCore
{
    public partial class PGP
    {
        /// <summary>
        /// Validates and exports public certificates. Secret keys and other packet types are rejected.
        /// An optional independently trusted primary fingerprint requires exactly one matching certificate.
        /// The caller retains both streams; callers must discard stream output when an exception occurs.
        /// </summary>
        public static void ExportPublicKeys(Stream input, Stream output, string expectedFingerprint = null, bool armor = true)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            PgpPublicKeyRing[] rings;
            try
            {
                rings = Utilities.ReadAllPgpObjects(input).Select(obj => obj is PgpPublicKeyRing ring
                    ? ring : throw new InvalidKeyMaterialException("Only public PGP certificates are accepted.")).ToArray();
            }
            catch (Exception ex) when (!(ex is PgpCoreException))
            {
                throw new InvalidKeyMaterialException("Failed to parse public PGP certificates.", ex);
            }
            if (rings.Length == 0) throw new InvalidKeyMaterialException("No public PGP certificate found.");
            foreach (var ring in rings) KeyRingValidation.Read(ring);
            if (expectedFingerprint != null)
            {
                string expected = expectedFingerprint.Replace(" ", "");
                if (expected.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) expected = expected.Substring(2);
                if ((expected.Length != 40 && expected.Length != 64) || expected.Any(c => !Uri.IsHexDigit(c)))
                    throw new ArgumentException("A complete primary key fingerprint is required.", nameof(expectedFingerprint));
                if (rings.Length != 1 || !string.Equals(Hex(rings[0].GetPublicKey().GetFingerprint()), expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidKeyMaterialException("The public certificate does not match the expected primary fingerprint.");
            }
            if (armor)
            {
                using (var armored = new ArmoredOutputStream(new NonClosingStream(output)))
                    foreach (var ring in rings) ring.Encode(armored);
            }
            else
                foreach (var ring in rings) ring.Encode(output);
        }

        /// <summary>Validates public certificates and replaces a file only after successful export.</summary>
        public static void ExportPublicKeys(Stream input, FileInfo output, string expectedFingerprint = null, bool armor = true)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            using (var staged = new AtomicFileOutput(output))
            {
                ExportPublicKeys(input, staged.Stream, expectedFingerprint, armor);
                staged.Commit();
            }
        }
    }
}
