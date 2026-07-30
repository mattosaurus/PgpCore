using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PgpCore.Abstractions;
using PgpCore.Enums;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
	public partial class PGP : IPGP
	{
		private const int BufferSize = 0x10000;
		private const string DefaultFileName = "name";

		/// <summary>
		/// OpenPGP packet tag of the AEAD (OCB) encrypted data packet. BouncyCastle has no entry for it and
		/// rejects it while reading the packet stream, so it is recognised by tag number in the error message.
		/// </summary>
		private const string AeadEncryptedDataPacketTag = "20";

		public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Zip;

		public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.Aes256;

		public int PgpSignatureType { get; set; } = PgpSignature.DefaultCertification;

		public PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; } = PublicKeyAlgorithmTag.RsaGeneral;

		public PGPFileType FileType { get; set; } = PGPFileType.Binary;

		public HashAlgorithmTag HashAlgorithmTag { get; set; } = HashAlgorithmTag.Sha256;

		public IEncryptionKeys EncryptionKeys { get; private set; }

		public bool AddVersionHeader { get; set; } = true;

		/// <summary>
		/// When true, decrypt operations tolerate a failed modification detection (MDC) integrity
		/// check instead of throwing <see cref="MessageIntegrityException"/>. Equivalent to
		/// gpg --ignore-mdc-error. Leave false unless you must read legacy data from senders that
		/// produce invalid MDC packets, as it disables tamper detection.
		/// </summary>
		public bool IgnoreIntegrityCheckFailure { get; set; } = false;

		#region Constructor

		public PGP()
		{ }

		public PGP(IEncryptionKeys encryptionKeys)
		{
			EncryptionKeys = encryptionKeys;
		}

		#endregion Constructor

		#region Private helpers

		#region OutputEncryptedAsync

		private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name, bool oldFormat)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				await OutputEncryptedAsync(inputFileStream, outputStream, withIntegrityCheck,
					name ?? inputFile.Name, oldFormat).ConfigureAwait(false);
			}
		}

		private async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, bool withIntegrityCheck,
			string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
					{
						await WriteOutputAndSignAsync(literalOut, inputStream, signatureGenerator).ConfigureAwait(false);
					}
					// The signature packet must follow the completed literal data packet; with
					// buffered (partial-length) literal packets the terminator is only written
					// when literalOut is disposed, so encode after the using block.
					signatureGenerator.Generate().Encode(compressedOut);
					await compressedOut.FlushAsync().ConfigureAwait(false);
				}
				await encryptedOut.FlushAsync().ConfigureAwait(false);
			}
		}

		#endregion OutputEncryptedAsync

		#region OutputSignedAsync

		private async Task OutputSignedAsync(FileInfo inputFile, Stream outputStream, string name, bool oldFormat)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				await OutputSignedAsync(inputFileStream, outputStream, name ?? inputFile.Name, oldFormat).ConfigureAwait(false);
			}
		}

		private async Task OutputSignedAsync(Stream inputStream, Stream outputStream,
			string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
				{
					await WriteOutputAndSignAsync(literalOut, inputStream, signatureGenerator).ConfigureAwait(false);
				}
				// See OutputEncryptedAsync: the signature must be encoded after the literal data
				// packet is completed by disposing literalOut.
				signatureGenerator.Generate().Encode(compressedOut);
				await compressedOut.FlushAsync().ConfigureAwait(false);
			}
		}

		#endregion OutputSignedAsync

		#region OutputClearSignedAsync

		private async Task OutputClearSignedAsync(FileInfo inputFile, Stream outputStream, IDictionary<string, string> headers)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				await OutputClearSignedAsync(inputFileStream, outputStream, headers).ConfigureAwait(false);
			}
		}

		private async Task OutputClearSignedAsync(Stream inputStream, Stream outputStream, IDictionary<string, string> headers)
		{
			using (StreamReader streamReader = new StreamReader(inputStream))
			using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers, AddVersionHeader))
			{
				PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

				bool anyLineWritten = false;
				while (streamReader.Peek() >= 0)
				{
					string line = await streamReader.ReadLineAsync().ConfigureAwait(false);
					if (line == null) continue;
					byte[] lineByteArray = Encoding.UTF8.GetBytes(line);
					// Does the line end with whitespace?
					// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
					string cleanLine = line.TrimEnd();
					byte[] cleanLineByteArray = Encoding.UTF8.GetBytes(cleanLine);

					pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
					await armoredOutputStream.WriteAsync(lineByteArray, 0, lineByteArray.Length).ConfigureAwait(false);

					// Add a line break back to the stream
					armoredOutputStream.Write((byte)'\r');
					armoredOutputStream.Write((byte)'\n');

					anyLineWritten = true;

					// Update signature with line breaks unless we're on the last line
					if (streamReader.Peek() >= 0)
					{
						pgpSignatureGenerator.Update((byte)'\r');
						pgpSignatureGenerator.Update((byte)'\n');
					}
				}

				// Empty content still needs a single (empty) cleartext line. Without one the armor has
				// an empty cleartext region that BouncyCastle's ArmoredInputStream cannot parse on the
				// way back in (VerifyClear throws "invalid header encountered"). gpg emits exactly this
				// empty line when clear-signing an empty file, so matching it keeps interop intact. The
				// signature is left covering zero canonical bytes, which is correct for a lone empty line.
				if (!anyLineWritten)
				{
					armoredOutputStream.Write((byte)'\r');
					armoredOutputStream.Write((byte)'\n');
				}

				armoredOutputStream.EndClearText();

				BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
				pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
			}
		}

		#endregion OutputClearSignedAsync

		#region WriteOutputAndSign

		private async Task WriteOutputAndSignAsync(Stream literalOut, Stream inputStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = await inputStream.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
			{
				await literalOut.WriteAsync(buf, 0, length).ConfigureAwait(false);
				signatureGenerator.Update(buf, 0, length);
			}

			await literalOut.FlushAsync().ConfigureAwait(false);
		}

		#endregion WriteOutputAndSign

		#region ChainEncryptedOut

		/// <summary>
		/// Translates BouncyCastle's "unknown packet type encountered: 20" into
		/// <see cref="UnsupportedAeadException"/>. Tag 20 is the AEAD (OCB) encrypted data packet, which the
		/// referenced BouncyCastle version cannot read. Reporting it as unrecognised or unencrypted data is
		/// misleading, because the input is valid OpenPGP and is encrypted.
		/// </summary>
		/// <param name="exception">The exception thrown while reading the packet stream.</param>
		/// <exception cref="UnsupportedAeadException">When the exception denotes an AEAD data packet.</exception>
		private static void ThrowIfAeadEncryptedData(Exception exception)
		{
			const string aeadPacketMarker = "unknown packet type encountered: " + AeadEncryptedDataPacketTag;

			if (exception?.Message == null ||
				exception.Message.IndexOf(aeadPacketMarker, StringComparison.OrdinalIgnoreCase) < 0)
			{
				return;
			}

			throw new UnsupportedAeadException(
				"The message uses AEAD (OCB) encryption, which the referenced BouncyCastle version cannot read. " +
				"Ask the sender to disable AEAD, or remove the AEAD feature flag from the key. " +
				"See https://github.com/mattosaurus/PgpCore/issues/219.",
				exception);
		}

		private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
		{
			var encryptedDataGenerator =
				new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

			AddEncryptionMethods(encryptedDataGenerator);

			return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
		}

		/// <summary>
		/// Adds every configured recipient to <paramref name="encryptedDataGenerator"/>: the chosen
		/// encryption key from each supplied public key ring, plus the symmetric key when one is set.
		/// </summary>
		/// <exception cref="NoEncryptionKeyException">
		/// When no encryption method is available at all. This previously surfaced as a
		/// <see cref="NullReferenceException"/> from iterating a null key ring collection.
		/// </exception>
		private void AddEncryptionMethods(PgpEncryptedDataGenerator encryptedDataGenerator)
		{
			int methodCount = 0;

			if (EncryptionKeys.PublicKeyRings != null)
			{
				foreach (PgpPublicKeyRingWithPreferredKey publicKeyRing in EncryptionKeys.PublicKeyRings)
				{
					PgpPublicKey publicKey = publicKeyRing.PreferredEncryptionKey ?? publicKeyRing.DefaultEncryptionKey;
					encryptedDataGenerator.AddMethod(publicKey);
					methodCount++;
				}
			}

			if (EncryptionKeys.SymmetricKey != null && EncryptionKeys.SymmetricKey.Length > 0)
			{
				encryptedDataGenerator.AddMethodRaw(EncryptionKeys.SymmetricKey, HashAlgorithmTag);
				methodCount++;
			}

			if (methodCount == 0)
				throw new NoEncryptionKeyException(
					"No encryption key is available. Supply a public key, a private key to derive one from, or a symmetric key.");
		}

		#endregion ChainEncryptedOut

		#region ChainCompressedOut

		private Stream ChainCompressedOut(Stream encryptedOut)
		{
			if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
			{
				PgpCompressedDataGenerator compressedDataGenerator =
					new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
				return compressedDataGenerator.Open(encryptedOut);
			}

			return encryptedOut;
		}

		#endregion ChainCompressedOut

		#region ChainLiteralOut

		private Stream ChainLiteralOut(Stream compressedOut, FileInfo file, string name, bool oldFormat)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator(oldFormat);

			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, file.Length,
				DateTime.UtcNow);
		}

		private Stream ChainLiteralOut(Stream compressedOut, Stream inputStream, string name, bool oldFormat)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator(oldFormat);
			return Utilities.OpenLiteralDataStream(pgpLiteralDataGenerator, compressedOut, FileTypeToChar(), name, inputStream);
		}

		#endregion ChainLiteralOut

		#region InitSignatureGenerator

		private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
		{
			PublicKeyAlgorithmTag tag = EncryptionKeys.SigningSecretKey.PublicKey.Algorithm;
			PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
			pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, EncryptionKeys.SigningPrivateKey);
			foreach (string userId in EncryptionKeys.SigningSecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.AddSignerUserId(false, userId);
				pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
				// Just the first one!
				break;
			}

			pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
			return pgpSignatureGenerator;
		}

		#endregion InitSignatureGenerator

		#region InitClearSignatureGenerator

		private PgpSignatureGenerator InitClearSignatureGenerator(ArmoredOutputStream armoredOutputStream)
		{
			PublicKeyAlgorithmTag tag = EncryptionKeys.SigningSecretKey.PublicKey.Algorithm;
			PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
			pgpSignatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, EncryptionKeys.SigningPrivateKey);
			armoredOutputStream.BeginClearText(HashAlgorithmTag);
			foreach (string userId in EncryptionKeys.SigningSecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.AddSignerUserId(false, userId);
				pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
				// Just the first one!
				break;
			}

			return pgpSignatureGenerator;
		}

		#endregion InitClearSignatureGenerator

		#region Misc Utilities

		private char FileTypeToChar()
		{
			if (FileType == PGPFileType.UTF8)
				return PgpLiteralData.Utf8;
			if (FileType == PGPFileType.Text)
				return PgpLiteralData.Text;
			return PgpLiteralData.Binary;
		}

		/// <summary>
		/// Writes a generated key as complete secret and public key rings. Exporting a single key pair
		/// would silently drop the encryption subkey that accompanies the master key (GitHub issue #285).
		/// </summary>
		private void ExportKeyRing(
			Stream secretOut,
			Stream publicOut,
			PgpSecretKeyRing secretKeyRing,
			PgpPublicKeyRing publicKeyRing,
			bool armor,
			bool emitVersion)
		{
			if (secretOut == null)
				throw new ArgumentNullException(nameof(secretOut));
			if (publicOut == null)
				throw new ArgumentNullException(nameof(publicOut));
			if (secretKeyRing == null)
				throw new ArgumentNullException(nameof(secretKeyRing));
			if (publicKeyRing == null)
				throw new ArgumentNullException(nameof(publicKeyRing));

			ArmoredOutputStream secretOutArmored;
			if (armor)
			{
				secretOutArmored = new ArmoredOutputStream(secretOut, AddVersionHeader);
				if (!emitVersion)
				{
					secretOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
				}

				secretOut = secretOutArmored;
			}
			else
			{
				secretOutArmored = null;
			}

			secretKeyRing.Encode(secretOut);

			secretOutArmored?.Dispose();

			ArmoredOutputStream publicOutArmored;
			if (armor)
			{
				publicOutArmored = new ArmoredOutputStream(publicOut, AddVersionHeader);
				if (!emitVersion)
				{
					publicOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
				}

				publicOut = publicOutArmored;
			}
			else
			{
				publicOutArmored = null;
			}

			publicKeyRing.Encode(publicOut);

			publicOutArmored?.Dispose();
		}

		private static int ReadInputLine(MemoryStream streamOut, Stream encodedFile)
		{
			streamOut.SetLength(0);

			int lookAhead = -1;
			int character;

			while ((character = encodedFile.ReadByte()) >= 0)
			{
				streamOut.WriteByte((byte)character);
				if (character == '\r' || character == '\n')
				{
					lookAhead = ReadPassedEol(streamOut, character, encodedFile);
					break;
				}
			}

			return lookAhead;
		}

		private static int ReadInputLine(MemoryStream streamOut, int lookAhead, Stream encodedFile)
		{
			streamOut.SetLength(0);

			int character = lookAhead;

			do
			{
				streamOut.WriteByte((byte)character);
				if (character == '\r' || character == '\n')
				{
					lookAhead = ReadPassedEol(streamOut, character, encodedFile);
					break;
				}
			} while ((character = encodedFile.ReadByte()) >= 0);

			if (character < 0)
			{
				lookAhead = -1;
			}

			return lookAhead;
		}

		private static int ReadPassedEol(MemoryStream streamOut, int lastCharacter, Stream encodedFile)
		{
			int lookAhead = encodedFile.ReadByte();

			if (lastCharacter == '\r' && lookAhead == '\n')
			{
				streamOut.WriteByte((byte)lookAhead);
				lookAhead = encodedFile.ReadByte();
			}

			return lookAhead;
		}

		private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
		{
			int end = line.Length - 1;

			while (end >= 0 && IsWhiteSpace(line[end]))
			{
				end--;
			}

			return end + 1;
		}

		private static int GetLengthWithoutWhiteSpace(byte[] line)
		{
			int end = line.Length - 1;

			while (end >= 0 && IsWhiteSpace(line[end]))
			{
				end--;
			}

			return end + 1;
		}

		private static bool IsWhiteSpace(byte b)
		{
			return IsLineEnding(b) || b == '\t' || b == ' ';
		}

		private static bool IsLineEnding(byte b)
		{
			return b == '\r' || b == '\n';
		}

		private static void ProcessLine(PgpSignature sig, byte[] line)
		{
			// note: trailing white space needs to be removed from the end of
			// each line for signature calculation RFC 4880 Section 7.1
			int length = GetLengthWithoutWhiteSpace(line);
			if (length > 0)
			{
				sig.Update(line, 0, length);
			}
		}

		private static byte[] LineSeparator => Encoding.ASCII.GetBytes(Environment.NewLine);

		public void Dispose()
		{ }

		#endregion Misc Utilities

		#endregion Private helpers

	}
}
