using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.Sig;
using PgpCore.Helpers;

namespace PgpCore
{
    /// <remarks>Basic utility class.</remarks>
    public static class Utilities
	{
		public static MPInteger[] DsaSigToMpi(
			byte[] encoding)
		{
			DerInteger i1, i2;

			try
			{
				Asn1Sequence s = (Asn1Sequence)Asn1Object.FromByteArray(encoding);

				i1 = (DerInteger)s[0];
				i2 = (DerInteger)s[1];
			}
			catch (IOException e)
			{
				throw new PgpException("exception encoding signature", e);
			}

			return new[] { new MPInteger(i1.Value), new MPInteger(i2.Value) };
		}

		public static MPInteger[] RsaSigToMpi(
			byte[] encoding)
		{
			return new[] { new MPInteger(new BigInteger(1, encoding)) };
		}

		public static string GetDigestName(
			HashAlgorithmTag hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
				case HashAlgorithmTag.Sha1:
					return "SHA1";
				case HashAlgorithmTag.MD2:
					return "MD2";
				case HashAlgorithmTag.MD5:
					return "MD5";
				case HashAlgorithmTag.RipeMD160:
					return "RIPEMD160";
				case HashAlgorithmTag.Sha224:
					return "SHA224";
				case HashAlgorithmTag.Sha256:
					return "SHA256";
				case HashAlgorithmTag.Sha384:
					return "SHA384";
				case HashAlgorithmTag.Sha512:
					return "SHA512";
				default:
					throw new PgpException("unknown hash algorithm tag in GetDigestName: " + hashAlgorithm);
			}
		}

		public static string GetSignatureName(
			PublicKeyAlgorithmTag keyAlgorithm,
			HashAlgorithmTag hashAlgorithm)
		{
			string encAlg;
			switch (keyAlgorithm)
			{
				case PublicKeyAlgorithmTag.RsaGeneral:
				case PublicKeyAlgorithmTag.RsaSign:
					encAlg = "RSA";
					break;
				case PublicKeyAlgorithmTag.Dsa:
					encAlg = "DSA";
					break;
				case PublicKeyAlgorithmTag.ECDH:
					encAlg = "ECDH";
					break;
				case PublicKeyAlgorithmTag.ECDsa:
					encAlg = "ECDSA";
					break;
				case PublicKeyAlgorithmTag.ElGamalEncrypt: // in some malformed cases.
				case PublicKeyAlgorithmTag.ElGamalGeneral:
					encAlg = "ElGamal";
					break;
				default:
					throw new PgpException("unknown algorithm tag in signature:" + keyAlgorithm);
			}

			return GetDigestName(hashAlgorithm) + "with" + encAlg;
		}

		public static string GetSymmetricCipherName(
			SymmetricKeyAlgorithmTag algorithm)
		{
			switch (algorithm)
			{
				case SymmetricKeyAlgorithmTag.Null:
					return null;
				case SymmetricKeyAlgorithmTag.TripleDes:
					return "DESEDE";
				case SymmetricKeyAlgorithmTag.Idea:
					return "IDEA";
				case SymmetricKeyAlgorithmTag.Cast5:
					return "CAST5";
				case SymmetricKeyAlgorithmTag.Blowfish:
					return "Blowfish";
				case SymmetricKeyAlgorithmTag.Safer:
					return "SAFER";
				case SymmetricKeyAlgorithmTag.Des:
					return "DES";
				case SymmetricKeyAlgorithmTag.Aes128:
					return "AES";
				case SymmetricKeyAlgorithmTag.Aes192:
					return "AES";
				case SymmetricKeyAlgorithmTag.Aes256:
					return "AES";
				case SymmetricKeyAlgorithmTag.Twofish:
					return "Twofish";
				case SymmetricKeyAlgorithmTag.Camellia128:
					return "Camellia";
				case SymmetricKeyAlgorithmTag.Camellia192:
					return "Camellia";
				case SymmetricKeyAlgorithmTag.Camellia256:
					return "Camellia";
				default:
					throw new PgpException("unknown symmetric algorithm: " + algorithm);
			}
		}

		public static int GetKeySize(SymmetricKeyAlgorithmTag algorithm)
		{
			int keySize;
			switch (algorithm)
			{
				case SymmetricKeyAlgorithmTag.Des:
					keySize = 64;
					break;
				case SymmetricKeyAlgorithmTag.Idea:
				case SymmetricKeyAlgorithmTag.Cast5:
				case SymmetricKeyAlgorithmTag.Blowfish:
				case SymmetricKeyAlgorithmTag.Safer:
				case SymmetricKeyAlgorithmTag.Aes128:
				case SymmetricKeyAlgorithmTag.Camellia128:
					keySize = 128;
					break;
				case SymmetricKeyAlgorithmTag.TripleDes:
				case SymmetricKeyAlgorithmTag.Aes192:
				case SymmetricKeyAlgorithmTag.Camellia192:
					keySize = 192;
					break;
				case SymmetricKeyAlgorithmTag.Aes256:
				case SymmetricKeyAlgorithmTag.Twofish:
				case SymmetricKeyAlgorithmTag.Camellia256:
					keySize = 256;
					break;
				default:
					throw new PgpException("unknown symmetric algorithm: " + algorithm);
			}

			return keySize;
		}

		public static KeyParameter MakeKey(
			SymmetricKeyAlgorithmTag algorithm,
			byte[] keyBytes)
		{
			string algName = GetSymmetricCipherName(algorithm);

			return ParameterUtilities.CreateKeyParameter(algName, keyBytes);
		}

		public static KeyParameter MakeRandomKey(
			SymmetricKeyAlgorithmTag algorithm,
			SecureRandom random)
		{
			int keySize = GetKeySize(algorithm);
			byte[] keyBytes = new byte[(keySize + 7) / 8];
			random.NextBytes(keyBytes);
			return MakeKey(algorithm, keyBytes);
		}

		public static KeyParameter MakeKeyFromPassPhrase(
			SymmetricKeyAlgorithmTag algorithm,
			S2k s2K,
			char[] passPhrase)
		{
			int keySize = GetKeySize(algorithm);
			byte[] pBytes = Strings.ToByteArray(new string(passPhrase));
			byte[] keyBytes = new byte[(keySize + 7) / 8];

			int generatedBytes = 0;
			int loopCount = 0;

			while (generatedBytes < keyBytes.Length)
			{
				IDigest digest;
				if (s2K != null)
				{
					string digestName = GetDigestName(s2K.HashAlgorithm);

					try
					{
						digest = DigestUtilities.GetDigest(digestName);
					}
					catch (Exception e)
					{
						throw new PgpException("can't find S2k digest", e);
					}

					for (int i = 0; i != loopCount; i++)
					{
						digest.Update(0);
					}

					byte[] iv = s2K.GetIV();

					switch (s2K.Type)
					{
						case S2k.Simple:
							digest.BlockUpdate(pBytes, 0, pBytes.Length);
							break;
						case S2k.Salted:
							digest.BlockUpdate(iv, 0, iv.Length);
							digest.BlockUpdate(pBytes, 0, pBytes.Length);
							break;
						case S2k.SaltedAndIterated:
							long count = s2K.IterationCount;
							digest.BlockUpdate(iv, 0, iv.Length);
							digest.BlockUpdate(pBytes, 0, pBytes.Length);

							count -= iv.Length + pBytes.Length;

							while (count > 0)
							{
								if (count < iv.Length)
								{
									digest.BlockUpdate(iv, 0, (int)count);
									break;
								}

								digest.BlockUpdate(iv, 0, iv.Length);
								count -= iv.Length;

								if (count < pBytes.Length)
								{
									digest.BlockUpdate(pBytes, 0, (int)count);
									count = 0;
								}
								else
								{
									digest.BlockUpdate(pBytes, 0, pBytes.Length);
									count -= pBytes.Length;
								}
							}

							break;
						default:
							throw new PgpException("unknown S2k type: " + s2K.Type);
					}
				}
				else
				{
					try
					{
						digest = DigestUtilities.GetDigest("MD5");

						for (int i = 0; i != loopCount; i++)
						{
							digest.Update(0);
						}

						digest.BlockUpdate(pBytes, 0, pBytes.Length);
					}
					catch (Exception e)
					{
						throw new PgpException("can't find MD5 digest", e);
					}
				}

				byte[] dig = DigestUtilities.DoFinal(digest);

				if (dig.Length > keyBytes.Length - generatedBytes)
				{
					Array.Copy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
				}
				else
				{
					Array.Copy(dig, 0, keyBytes, generatedBytes, dig.Length);
				}

				generatedBytes += dig.Length;

				loopCount++;
			}

			Array.Clear(pBytes, 0, pBytes.Length);

			return MakeKey(algorithm, keyBytes);
		}

		/// <summary>Write out the passed in file as a literal data packet.</summary>
		public static async Task WriteFileToLiteralDataAsync(
			Stream output,
			char fileType,
			FileInfo file)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime);
			await PipeFileContentsAsync(file, pOut, 4096);
			lData.Close();
		}

		/// <summary>Write out the passed in file as a literal data packet.</summary>
		public static void WriteFileToLiteralData(
			Stream output,
			char fileType,
			FileInfo file)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime);
			PipeFileContents(file, pOut, 4096);
			lData.Close();
		}

		/// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
		public static async Task WriteFileToLiteralDataAsync(
			Stream output,
			char fileType,
			FileInfo file,
			byte[] buffer)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer);
			await PipeFileContentsAsync(file, pOut, buffer.Length);
			lData.Close();
		}

		/// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
		public static void WriteFileToLiteralData(
			Stream output,
			char fileType,
			FileInfo file,
			byte[] buffer)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer);
			PipeFileContents(file, pOut, buffer.Length);
			lData.Close();
		}

		public static async Task WriteStreamToLiteralDataAsync(
			Stream output,
			char fileType,
			Stream input,
			string name)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
			await PipeStreamContentsAsync(input, pOut, 4096);
			lData.Close();
		}

		public static void WriteStreamToLiteralData(
			Stream output,
			char fileType,
			Stream input,
			string name)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
			PipeStreamContents(input, pOut, 4096);
			lData.Close();
		}

		public static async Task WriteStreamToLiteralDataAsync(
			Stream output,
			char fileType,
			Stream input,
			byte[] buffer,
			string name)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, name, DateTime.Now, buffer);
			await PipeStreamContentsAsync(input, pOut, buffer.Length);
			lData.Close();
		}

		public static void WriteStreamToLiteralData(
			Stream output,
			char fileType,
			Stream input,
			byte[] buffer,
			string name)
		{
			PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
			Stream pOut = lData.Open(output, fileType, name, DateTime.Now, buffer);
			PipeStreamContents(input, pOut, buffer.Length);
			lData.Close();
		}

		/// <summary>
		/// Opens a key ring file and returns first available sub-key suitable for encryption.
		/// If such sub-key is not found, return master key that can encrypt.
		/// </summary>
		/// <param name="publicKeyStream">Input stream containing the public key contents</param>
		/// <returns></returns>
		public static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
		{
			using (Stream inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
			{
				PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

				// we just loop through the collection till we find a key suitable for encryption, in the real
				// world you would probably want to be a bit smarter about this.
				// iterate through the key rings.
				foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
				{
					List<PgpPublicKey> keys = kRing.GetPublicKeys()
						.Cast<PgpPublicKey>()
						.Where(k => k.IsEncryptionKey).ToList();

					const int encryptKeyFlags = PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage;

					foreach (PgpPublicKey key in keys.Where(k => k.Version >= 4))
					{
						foreach (PgpSignature s in key.GetSignatures())
						{
							if (s.HasSubpackets && s.GetHashedSubPackets().GetKeyFlags() == encryptKeyFlags)
								return key;
						}
					}

					if (keys.Any())
						return keys.First();
				}
			}

			throw new ArgumentException("Can't find encryption key in key ring.");
		}

		/// <summary>
		/// Parses a public key
		/// </summary>
		/// <param name="publicKey">The plain text value of the public key</param>
		/// <returns></returns>
		public static PgpPublicKey ReadPublicKey(string publicKey)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new FileNotFoundException("Public key was not provided");

			return ReadPublicKey(publicKey.GetStream());
		}

		/// <summary>
		/// Parses a public key
		/// </summary>
		/// <param name="publicKeyFile">The path to the public key file</param>
		/// <returns></returns>
		public static PgpPublicKey ReadPublicKey(FileInfo publicKeyFile)
		{
			if (!publicKeyFile.Exists)
				throw new FileNotFoundException($"File {publicKeyFile} was not found");
			using (FileStream fs = publicKeyFile.OpenRead())
				return ReadPublicKey(fs);
		}

		/// <summary>
		/// Constructs the PublicKeyRingBundle from a file
		/// </summary>
		/// <param name="publicKeyFile"></param>
		/// <returns></returns>
		/// <exception cref="FileNotFoundException"></exception>
		public static PgpPublicKeyRingBundle ReadPublicKeyRingBundle(FileInfo publicKeyFile)
		{
			if (!publicKeyFile.Exists)
				throw new FileNotFoundException($"File {publicKeyFile} was not found");
			using (FileStream fs = publicKeyFile.OpenRead())
				return ReadPublicKeyRingBundle(fs);
		}

		/// <summary>
		/// Opens a key ring file and returns all public keys found.
		/// </summary>
		/// <param name="publicKeyStream">Input stream containing the public key contents</param>
		/// <returns></returns>
		public static PgpPublicKeyRingBundle ReadPublicKeyRingBundle(Stream publicKeyStream)
		{
			using (Stream inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
				return new PgpPublicKeyRingBundle(inputStream);
		}

		/// <summary>
		/// Returns all public key rings from multiple public key streams
		/// </summary>
		/// <param name="publicKeyStreams"></param>
		/// <returns></returns>
		public static IEnumerable<PgpPublicKeyRing> ReadAllKeyRings(IEnumerable<Stream> publicKeyStreams)
		{
			var publicKeyBundles = publicKeyStreams.Select(ReadPublicKeyRingBundle);
			return ReadAllKeyRings(publicKeyBundles);
		}

		/// <summary>
		/// Returns all public key rings from a public key stream
		/// </summary>
		/// <param name="publicKeyStream"></param>
		/// <returns></returns>
		public static IEnumerable<PgpPublicKeyRing> ReadAllKeyRings(Stream publicKeyStream)
		{
			var publicKeyBundles = ReadPublicKeyRingBundle(publicKeyStream);
			return publicKeyBundles.GetKeyRings().Cast<PgpPublicKeyRing>();
		}

		private static IEnumerable<PgpPublicKeyRing> ReadAllKeyRings(
			IEnumerable<PgpPublicKeyRingBundle> publicKeyRingBundles)
		{
			return publicKeyRingBundles.SelectMany(bundle => bundle.GetKeyRings().Cast<PgpPublicKeyRing>());
		}

		/// <summary>
		/// Returns the secret key ring bundle from a private key stream
		/// </summary>
		/// <param name="privateKeyStream"></param>
		/// <returns></returns>
		public static PgpSecretKeyRingBundle ReadSecretKeyRingBundle(Stream privateKeyStream)
		{
			using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
				return new PgpSecretKeyRingBundle(inputStream);
		}

		/// <summary>
		/// Finds and returns the public key most suitable for verification in a key ring. Master keys are prioritized
		/// </summary>
		/// <param name="publicKeys"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentException"></exception>
		public static PgpPublicKey FindBestVerificationKey(PgpPublicKeyRing publicKeys)
		{
			PgpPublicKey[] keys = publicKeys.GetPublicKeys().Cast<PgpPublicKey>().ToArray();

			// Has Key Flags for signing content
			PgpPublicKey[] verificationKeys = keys.Where(key => GetSigningScore(key) >= 3).ToArray();
			// Failsafe, get master key with signing capabilities.
			if (!verificationKeys.Any())
				verificationKeys = keys.Where(key => GetSigningScore(key) >= 1).ToArray();

			PgpPublicKey signingKey = verificationKeys.OrderByDescending(GetSigningScore).FirstOrDefault();
			if (signingKey == null)
				throw new ArgumentException("No verification keys in keyring");

			return signingKey;
		}

		/// <summary>
		/// Finds and returns the public key most suitable for encryption in a key ring. Master keys are prioritized
		/// </summary>
		/// <param name="publicKeys"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentException"></exception>
		public static PgpPublicKey FindBestEncryptionKey(PgpPublicKeyRing publicKeys)
		{
			PgpPublicKey[] keys = publicKeys.GetPublicKeys().Cast<PgpPublicKey>().ToArray();
			// Is encryption key and has the two encryption key flags
			PgpPublicKey[] encryptKeys = keys.Where(key => GetEncryptionScore(key) >= 4).ToArray();

			// If no suitable encryption keys are found, get master key with encryption capability
			if (!encryptKeys
				    .Any())
				encryptKeys = keys.Where(key => GetEncryptionScore(key) >= 3).ToArray();

			// Otherwise get any keys with encryption capability
			if (!encryptKeys
					.Any())
				encryptKeys = keys.Where(key => GetEncryptionScore(key) >= 2).ToArray();

			PgpPublicKey encryptionKey = encryptKeys.OrderByDescending(GetEncryptionScore).FirstOrDefault();
			if (encryptionKey == null)
				throw new ArgumentException("No encryption keys in keyring");
			return encryptionKey;
		}

		/// <summary>
		/// Finds the first secret key in the key ring suitable for signing. 
		/// </summary>
		/// <param name="secretKeyRingBundle">The key ring bundle to search</param>
		/// <returns></returns>
		/// <exception cref="ArgumentException">When no rings are suitable for signing</exception>
		public static PgpSecretKey FindBestSigningKey(PgpSecretKeyRingBundle secretKeyRingBundle)
		{
			PgpSecretKeyRing[] keyRings = secretKeyRingBundle.GetKeyRings().Cast<PgpSecretKeyRing>().ToArray();

			var secretKeys = keyRings.SelectMany(ring => ring.GetSecretKeys().Cast<PgpSecretKey>())
				.OrderByDescending(GetSigningScore).ToArray();
			
			if(!secretKeys.Any())
				throw new ArgumentException("Could not find any signing keys in keyring");
			return secretKeys.First();
		}

		/// <summary>
		/// Finds and returns the master key
		/// </summary>
		/// <param name="publicKeys"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentException"></exception>
		public static PgpPublicKey FindMasterKey(PgpPublicKeyRing publicKeys)
		{
			PgpPublicKey[] keys = publicKeys.GetPublicKeys().Cast<PgpPublicKey>().ToArray();

			return keys.Single(x => x.IsMasterKey);
		}

		/// <summary>
		/// Checks if the key with the given id is present in the collection of public keys, and if it is, return it.
		/// </summary>
		/// <param name="keyId"></param>
		/// <param name="verificationKeys"></param>
		/// <param name="verificationKey"></param>
		/// <returns></returns>
		public static bool FindPublicKey(long keyId, IEnumerable<PgpPublicKey> verificationKeys,
			out PgpPublicKey verificationKey)
		{
			var foundKeys = verificationKeys.Where(key =>
				key.KeyId == keyId ||
				key.GetSignatures().Cast<PgpSignature>().Any(signature => signature.KeyId == keyId)).ToArray();
			verificationKey = foundKeys.FirstOrDefault();
			return foundKeys.Any();
		}

		public static bool FindPublicKeyInKeyRings(long keyId, IEnumerable<PgpPublicKeyRing> publicKeyRings,
			out PgpPublicKey verificationKey)
		{
			verificationKey = null;

			foreach (PgpPublicKeyRing publicKeyRing in publicKeyRings)
			{
				var verificationKeys = publicKeyRing.GetPublicKeys();
				if (FindPublicKey(keyId, verificationKeys, out verificationKey))
					return true;
			}

			return false;
		}

		private static async Task PipeFileContentsAsync(FileInfo file, Stream pOut, int bufSize)
		{
			using (FileStream inputStream = file.OpenRead())
			{
				byte[] buf = new byte[bufSize];

				int len;
				while ((len = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
				{
					await pOut.WriteAsync(buf, 0, len);
				}
			}
		}

		private static void PipeFileContents(FileInfo file, Stream pOut, int bufSize)
		{
			using (FileStream inputStream = file.OpenRead())
			{
				byte[] buf = new byte[bufSize];

				int len;
				while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
				{
					pOut.Write(buf, 0, len);
				}
			}
		}

		private static async Task PipeStreamContentsAsync(Stream input, Stream pOut, int bufSize)
		{
			byte[] buf = new byte[bufSize];

			int len;
			while ((len = await input.ReadAsync(buf, 0, buf.Length)) > 0)
			{
				await pOut.WriteAsync(buf, 0, len);
			}
		}

		private static void PipeStreamContents(Stream input, Stream pOut, int bufSize)
		{
			byte[] buf = new byte[bufSize];

			int len;
			while ((len = input.Read(buf, 0, buf.Length)) > 0)
			{
				pOut.Write(buf, 0, len);
			}
		}

		private const int ReadAhead = 60;

		private static bool IsPossiblyBase64(
			int ch)
		{
			return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
			                              || ch >= '0' && ch <= '9' || ch == '+' || ch == '/'
			                              || ch == '\r' || ch == '\n';
		}

		/// <summary>
		/// Return either an ArmoredInputStream or a BcpgInputStream based on whether
		/// the initial characters of the stream are binary PGP encodings or not.
		/// </summary>
		public static Stream GetDecoderStream(
			Stream inputStream)
		{
			// TODO Remove this restriction?
			if (!inputStream.CanSeek)
				throw new ArgumentException("inputStream must be seek-able", nameof(inputStream));

			long markedPos = inputStream.Position;

			int ch = inputStream.ReadByte();
			if ((ch & 0x80) != 0)
			{
				inputStream.Position = markedPos;

				return inputStream;
			}

			if (!IsPossiblyBase64(ch))
			{
				inputStream.Position = markedPos;

				return new ArmoredInputStream(inputStream);
			}

			byte[] buf = new byte[ReadAhead];
			int count = 1;
			int index = 1;

			buf[0] = (byte)ch;
			while (count != ReadAhead && (ch = inputStream.ReadByte()) >= 0)
			{
				if (!IsPossiblyBase64(ch))
				{
					inputStream.Position = markedPos;

					return new ArmoredInputStream(inputStream);
				}

				if (ch != '\n' && ch != '\r')
				{
					buf[index++] = (byte)ch;
				}

				count++;
			}

			inputStream.Position = markedPos;

			//
			// nothing but new lines, little else, assume regular armoring
			//
			if (count < 4)
			{
				return new ArmoredInputStream(inputStream);
			}

			//
			// test our non-blank data
			//
			byte[] firstBlock = new byte[8];
			Array.Copy(buf, 0, firstBlock, 0, firstBlock.Length);
			byte[] decoded = Base64.Decode(firstBlock);

			//
			// it's a base64 PGP block.
			//
			bool hasHeaders = (decoded[0] & 0x80) == 0;

			return new ArmoredInputStream(inputStream, hasHeaders);
		}

		public static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(Stream encodedFile)
		{
			PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(encodedFile);
			return ExtractPublicKey(encryptedDataList);
		}

		public static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(PgpEncryptedDataList encryptedDataList)
		{
			return ExtractPublicKey(encryptedDataList);
		}

		public static PgpObject ProcessCompressedMessage(PgpObject message)
		{
			PgpCompressedData compressedData = (PgpCompressedData)message;
			Stream compressedDataStream = compressedData.GetDataStream();
			PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedDataStream);
			message = CheckForOnePassSignatureList(compressedFactory);
			return message;
		}

		public static PgpObject CheckForOnePassSignatureList(PgpObjectFactory compressedFactory)
		{
			var message = compressedFactory.NextPgpObject();
			if (message is PgpOnePassSignatureList)
			{
				message = compressedFactory.NextPgpObject();
			}

			return message;
		}

		public static PgpObject SkipSignatureList(PgpObjectFactory compressedFactory)
		{
			var message = compressedFactory.NextPgpObject();
			while (message is PgpOnePassSignatureList || message is PgpSignatureList)
			{
				message = compressedFactory.NextPgpObject();
			}

			return message;
		}


		public static PgpObjectFactory GetClearDataStream(PgpPrivateKey privateKey,
			PgpPublicKeyEncryptedData publicKeyEncryptedData)
		{
			Stream clearStream = publicKeyEncryptedData.GetDataStream(privateKey);
			PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
			return clearFactory;
		}

		public static PgpPublicKeyEncryptedData ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
		{
			return encryptedDataList.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>()
				.FirstOrDefault(encryptedData => encryptedData != null);
		}

		public static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
		{
			var factory = new PgpObjectFactory(encodedFile);
			PgpObject pgpObject = factory.NextPgpObject();

			PgpEncryptedDataList encryptedDataList;

			if (pgpObject is PgpEncryptedDataList dataList)
			{
				encryptedDataList = dataList;
			}
			else
			{
				encryptedDataList = (PgpEncryptedDataList)factory.NextPgpObject();
			}

			return encryptedDataList;
		}

		public static PgpOnePassSignatureList GetPgpOnePassSignatureList(Stream encodedFile)
		{
			var factory = new PgpObjectFactory(encodedFile);
			PgpObject pgpObject = factory.NextPgpObject();

			PgpOnePassSignatureList pgpOnePassSignatureList;

			if (pgpObject is PgpOnePassSignatureList onePassSignatureList)
			{
				pgpOnePassSignatureList = onePassSignatureList;
			}
			else
			{
				pgpOnePassSignatureList = (PgpOnePassSignatureList)factory.NextPgpObject();
			}

			return pgpOnePassSignatureList;
		}

		/// <summary>
		/// Scores the public key for how suitable it is as an encryption key
		/// Master key += 1
		/// IsEncryptionKey += 2
		/// Either of the encryption flags += 1 (for each)
		/// Highest score is 5
		/// </summary>
		/// <param name="key"></param>
		/// <returns></returns>
		private static int GetEncryptionScore(PgpPublicKey key)
		{
			int score = 0;
			if (key.IsMasterKey)
				score += 1;
			if (key.IsEncryptionKey)
				score += 2;
			PgpSignature[] signatures = key.GetSignatures().Cast<PgpSignature>()
				.Where(signature => signature.HasSubpackets).ToArray();

			if (signatures.Any(signature =>
				    (signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.EncryptComms) > 0))
				score += 1;
			if (signatures.Any(signature =>
				    (signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.EncryptStorage) > 0))
				score += 1;
			return score;
		}

		/// <summary>
		/// Scores the public key for how suitable it is as a verification key
		/// Master key += 1
		/// Signing key flag += 2
		/// Highest score is 3
		/// </summary>
		/// <param name="key"></param>
		/// <returns></returns>
		private static int GetSigningScore(PgpPublicKey key)
		{
			int score = 0;
			if (key.IsMasterKey)
				score += 1;
			var signatures = key.GetSignatures().Cast<PgpSignature>();
			if (signatures.Any(signature => signature.HasSubpackets &&
			                                (signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.SignData) > 0))
				score += 2;
			return score;
		}

		/// <summary>
		/// Scores the secret key for how suitable it is as a signing key
		/// Master key += 1
		/// IsSigningKey += 2
		/// Signing key flag += 2
		/// Highest score is 5
		/// </summary>
		/// <param name="key"></param>
		/// <returns></returns>
		private static int GetSigningScore(PgpSecretKey key)
		{
			int score = 0;
			if (key.IsSigningKey)
				score += 2;
			score += GetSigningScore(key.PublicKey);
			return score;
		}
	}
}