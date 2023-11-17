using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PgpCore.Abstractions;
using PgpCore.Enums;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class PGP
	{
		public static PGP Instance => _instance ?? (_instance = new PGP());
		private static PGP _instance;

		private const int BufferSize = 0x10000;
		private const string DefaultFileName = "name";

		public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Uncompressed;

		public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.TripleDes;

		public int PgpSignatureType { get; set; } = PgpSignature.DefaultCertification;

		public PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; } = PublicKeyAlgorithmTag.RsaGeneral;

		public PGPFileType FileType { get; set; } = PGPFileType.Binary;

		public HashAlgorithmTag HashAlgorithmTag { get; set; } = HashAlgorithmTag.Sha1;

		public IEncryptionKeys EncryptionKeys { get; private set; }

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

		private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
					{
						using (FileStream inputFileStream = inputFile.OpenRead())
						{
							await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream,
								signatureGenerator);
						}
					}
				}
			}
		}

		private async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, bool withIntegrityCheck,
			string name)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
					{
						await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
					}
				}
			}
		}

		#endregion OutputEncryptedAsync

		#region OutputEncrypted

		private void OutputEncrypted(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
					{
						using (FileStream inputFileStream = inputFile.OpenRead())
						{
							WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
						}
					}
				}
			}
		}

		private void OutputEncrypted(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
					{
						WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
					}
				}
			}
		}

		#endregion OutputEncrypted

		#region OutputSignedAsync

		private async Task OutputSignedAsync(FileInfo inputFile, Stream outputStream)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
				{
					using (FileStream inputFileStream = inputFile.OpenRead())
					{
						await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator);
					}
				}
			}
		}

		private async Task OutputSignedAsync(Stream inputStream, Stream outputStream,
			string name)
		{
			Stream compressedOut = ChainCompressedOut(outputStream);

			PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
			using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
			{
				await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
			}
		}

		#endregion OutputSignedAsync

		#region OutputSigned

		private void OutputSigned(FileInfo inputFile, Stream outputStream)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile))
				{
					using (FileStream inputFileStream = inputFile.OpenRead())
					{
						WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
					}
				}
			}
		}

		private void OutputSigned(Stream inputStream, Stream outputStream, string name)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name))
				{
					WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
				}
			}
		}

		#endregion OutputSigned

		#region OutputClearSignedAsync

		private async Task OutputClearSignedAsync(FileInfo inputFile, Stream outputStream)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				await OutputClearSignedAsync(inputFileStream, outputStream);
			}
		}

		private async Task OutputClearSignedAsync(Stream inputStream, Stream outputStream)
		{
			using (StreamReader streamReader = new StreamReader(inputStream))
			using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
			{
				PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

				while (streamReader.Peek() >= 0)
				{
					string line = await streamReader.ReadLineAsync();
					byte[] lineByteArray = Encoding.ASCII.GetBytes(line);
					// Does the line end with whitespace?
					// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
					string cleanLine = line.TrimEnd();
					byte[] cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

					pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
					await armoredOutputStream.WriteAsync(lineByteArray, 0, lineByteArray.Length);

					// Add a line break back to the stream
					armoredOutputStream.Write((byte)'\r');
					armoredOutputStream.Write((byte)'\n');

					// Update signature with line breaks unless we're on the last line
					if (streamReader.Peek() >= 0)
					{
						pgpSignatureGenerator.Update((byte)'\r');
						pgpSignatureGenerator.Update((byte)'\n');
					}
				}

				armoredOutputStream.EndClearText();

				BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
				pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
			}
		}

		#endregion OutputClearSignedAsync

		#region OutputClearSigned

		private void OutputClearSigned(FileInfo inputFile, Stream outputStream)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				OutputClearSigned(inputFileStream, outputStream);
			}
		}

		private void OutputClearSigned(Stream inputStream, Stream outputStream)
		{
			using (StreamReader streamReader = new StreamReader(inputStream))
			using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
			{
				PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

				while (streamReader.Peek() >= 0)
				{
					string line = streamReader.ReadLine();
					if (line == null) continue;
					byte[] lineByteArray = Encoding.ASCII.GetBytes(line);
					// Does the line end with whitespace?
					// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
					string cleanLine = line.TrimEnd();
					byte[] cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

					pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
					armoredOutputStream.Write(lineByteArray, 0, lineByteArray.Length);

					// Add a line break back to the stream
					armoredOutputStream.Write((byte)'\r');
					armoredOutputStream.Write((byte)'\n');

					// Update signature with line breaks unless we're on the last line
					if (streamReader.Peek() >= 0)
					{
						pgpSignatureGenerator.Update((byte)'\r');
						pgpSignatureGenerator.Update((byte)'\n');
					}
				}

				armoredOutputStream.EndClearText();

				BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
				pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
			}
		}

		#endregion OutputClearSigned

		#region DecryptAsync

		/// <summary>
		/// PGP decrypt a given stream.
		/// </summary>
		/// <param name="inputStream">PGP encrypted data stream</param>
		/// <param name="outputStream">Output PGP decrypted stream</param>
		/// <returns></returns>
		private async Task DecryptAsync(Stream inputStream, Stream outputStream)
		{
			if (inputStream == null)
				throw new ArgumentException("InputStream");
			if (outputStream == null)
				throw new ArgumentException("OutputStream");

			PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

			PgpObject obj = objFactory.NextPgpObject();

			// the first object might be a PGP marker packet.
			PgpEncryptedDataList enc = null;
			PgpObject message = null;

			if (obj is PgpEncryptedDataList dataList)
				enc = dataList;
			else if (obj is PgpCompressedData compressedData)
				message = compressedData;
			else
				enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

			// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
			if (enc == null && message == null)
				throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

			using (CompositeDisposable disposables = new CompositeDisposable())
			{
				// decrypt
				PgpPrivateKey privateKey = null;
				PgpPublicKeyEncryptedData pbe = null;
				if (enc != null)
				{
					foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in enc.GetEncryptedDataObjects())
					{
						privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

						if (privateKey != null)
						{
							pbe = publicKeyEncryptedData;
							break;
						}
					}

					if (privateKey == null)
						throw new ArgumentException("Secret key for message not found.");

					Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
					PgpObjectFactory plainFact = new PgpObjectFactory(clear);

					message = plainFact.NextPgpObject();

					if (message is PgpOnePassSignatureList || message is PgpSignatureList)
					{
						message = plainFact.NextPgpObject();
					}
				}

				if (message is PgpCompressedData pgpCompressedData)
				{
					Stream compDataIn = pgpCompressedData.GetDataStream().DisposeWith(disposables);
					PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
					message = objectFactory.NextPgpObject();

					if (message is PgpOnePassSignatureList || message is PgpSignatureList)
					{
						message = objectFactory.NextPgpObject();
						var literalData = (PgpLiteralData)message;
						Stream unc = literalData.GetInputStream();
						await StreamHelper.PipeAllAsync(unc, outputStream);
					}
					else
					{
						PgpLiteralData literalData = (PgpLiteralData)message;
						Stream unc = literalData.GetInputStream();
						await StreamHelper.PipeAllAsync(unc, outputStream);
					}
				}
				else if (message is PgpLiteralData literalData)
				{
					Stream unc = literalData.GetInputStream();
					await StreamHelper.PipeAllAsync(unc, outputStream);

					if (pbe.IsIntegrityProtected())
					{
						if (!pbe.Verify())
						{
							throw new PgpException("Message failed integrity check.");
						}
					}
				}
				else if (message is PgpOnePassSignatureList)
					throw new PgpException("Encrypted message contains a signed message - not literal data.");
				else
					throw new PgpException("Message is not a simple encrypted file.");
			}
		}

		#endregion DecryptAsync

		#region Decrypt

		/// <summary>
		/// PGP decrypt a given stream.
		/// </summary>
		/// <param name="inputStream">PGP encrypted data stream</param>
		/// <param name="outputStream">Output PGP decrypted stream</param>
		/// <returns></returns>
		private void Decrypt(Stream inputStream, Stream outputStream)
		{
			if (inputStream == null)
				throw new ArgumentException("InputStream");
			if (outputStream == null)
				throw new ArgumentException("OutputStream");

			PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

			PgpObject obj = objFactory.NextPgpObject();

			// the first object might be a PGP marker packet.
			PgpEncryptedDataList enc = null;
			PgpObject message = null;

			if (obj is PgpEncryptedDataList dataList)
				enc = dataList;
			else if (obj is PgpCompressedData compressedData)
				message = compressedData;
			else
				enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

			// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
			if (enc == null && message == null)
				throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

			using (CompositeDisposable disposables = new CompositeDisposable())
			{
				// decrypt
				PgpPrivateKey privateKey = null;
				PgpPublicKeyEncryptedData pbe = null;
				if (enc != null)
				{
					foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in enc.GetEncryptedDataObjects())
					{
						privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

						if (privateKey != null)
						{
							pbe = publicKeyEncryptedData;
							break;
						}
					}

					if (privateKey == null)
						throw new ArgumentException("Secret key for message not found.");

					Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
					PgpObjectFactory plainFact = new PgpObjectFactory(clear);

					message = plainFact.NextPgpObject();

					if (message is PgpOnePassSignatureList || message is PgpSignatureList)
					{
						message = plainFact.NextPgpObject();
					}
				}

				if (message is PgpCompressedData pgpCompressedData)
				{
					Stream compDataIn = pgpCompressedData.GetDataStream().DisposeWith(disposables);
					PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
					message = objectFactory.NextPgpObject();

					if (message is PgpOnePassSignatureList || message is PgpSignatureList)
					{
						message = objectFactory.NextPgpObject();
						PgpLiteralData literalData = (PgpLiteralData)message;
						Stream unc = literalData.GetInputStream();
						StreamHelper.PipeAll(unc, outputStream);
					}
					else
					{
						PgpLiteralData literalData = (PgpLiteralData)message;
						Stream unc = literalData.GetInputStream();
						StreamHelper.PipeAll(unc, outputStream);
					}
				}
				else if (message is PgpLiteralData literalData)
				{
					Stream unc = literalData.GetInputStream();
					StreamHelper.PipeAll(unc, outputStream);

					if (pbe.IsIntegrityProtected())
					{
						if (!pbe.Verify())
						{
							throw new PgpException("Message failed integrity check.");
						}
					}
				}
				else if (message is PgpOnePassSignatureList)
					throw new PgpException("Encrypted message contains a signed message - not literal data.");
				else
					throw new PgpException("Message is not a simple encrypted file.");
			}
		}

		#endregion Decrypt

		#region DecryptAndVerifyAsync

		/// <summary>
		/// PGP decrypt and verify a given stream.
		/// </summary>
		/// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
		/// <param name="outputStream">Output PGP decrypted and verified stream</param>
		private async Task DecryptAndVerifyAsync(Stream inputStream, Stream outputStream)
		{
			PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

			PgpObject obj = objFactory.NextPgpObject();

			// the first object might be a PGP marker packet.
			PgpEncryptedDataList encryptedDataList = null;
			PgpObject message = null;

			if (obj is PgpEncryptedDataList dataList)
				encryptedDataList = dataList;
			else if (obj is PgpCompressedData compressedData)
				message = compressedData;
			else
				encryptedDataList = (PgpEncryptedDataList)objFactory.NextPgpObject();

			// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
			if (encryptedDataList == null && message == null)
				throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

			using (CompositeDisposable disposables = new CompositeDisposable())
			{
				// decrypt
				PgpPrivateKey privateKey = null;
				PgpPublicKeyEncryptedData pbe = null;
				if (encryptedDataList != null)
				{
					foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in
							 encryptedDataList.GetEncryptedDataObjects())
					{
						privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

						if (privateKey != null)
						{
							pbe = publicKeyEncryptedData;
							break;
						}
					}

					if (privateKey == null)
						throw new ArgumentException("Secret key for message not found.");

					Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
					PgpObjectFactory plainFact = new PgpObjectFactory(clear);

					message = plainFact.NextPgpObject();

					if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
					{
						PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
						var keyIdToVerify = pgpOnePassSignature.KeyId;

						var verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
							out PgpPublicKey _);
						if (verified == false)
							throw new PgpException("Failed to verify file.");

						message = plainFact.NextPgpObject();
					}
					else if (message is PgpSignatureList pgpSignatureList)
					{
						PgpSignature pgpSignature = pgpSignatureList[0];
						var keyIdToVerify = pgpSignature.KeyId;

						var verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
							out PgpPublicKey _);
						if (verified == false)
							throw new PgpException("Failed to verify file.");

						message = plainFact.NextPgpObject();
					}
					else if (!(message is PgpCompressedData))
						throw new PgpException("File was not signed.");
				}

				if (message is PgpCompressedData cData)
				{
                    Stream compDataIn = cData.GetDataStream().DisposeWith(disposables);
                    PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
                    message = objectFactory.NextPgpObject();

                    long? keyIdToVerify = null;

                    if (message is PgpSignatureList pgpSignatureList)
                    {
                        keyIdToVerify = pgpSignatureList[0].KeyId;
                    }
                    else if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                    {
                        PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                        keyIdToVerify = pgpOnePassSignature.KeyId;
                    }

                    if (keyIdToVerify.HasValue)
                    {
                        var verified = Utilities.FindPublicKey(keyIdToVerify.Value, EncryptionKeys.VerificationKeys,
                            out PgpPublicKey _);
                        if (verified == false)
                            throw new PgpException("Failed to verify file.");
                        
                        message = objectFactory.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        await StreamHelper.PipeAllAsync(unc, outputStream);
                    }
                    else
                    {
                        throw new PgpException("File was not signed.");
                    }
                }
				else if (message is PgpLiteralData literalData)
				{
					Stream unc = literalData.GetInputStream();
					await StreamHelper.PipeAllAsync(unc, outputStream);

					if (pbe.IsIntegrityProtected())
					{
						if (!pbe.Verify())
						{
							throw new PgpException("Message failed integrity check.");
						}
					}
				}
				else
					throw new PgpException("File was not signed.");
			}
		}

		#endregion DecryptAndVerifyAsync

		#region DecryptAndVerify

		/// <summary>
		/// PGP decrypt and verify a given stream.
		/// </summary>
		/// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
		/// <param name="outputStream">Output PGP decrypted and verified stream</param>
		private void DecryptAndVerify(Stream inputStream, Stream outputStream)
		{
			PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

			PgpObject obj = objFactory.NextPgpObject();

			// the first object might be a PGP marker packet.
			PgpEncryptedDataList encryptedDataList = null;
			PgpObject message = null;

			if (obj is PgpEncryptedDataList dataList)
				encryptedDataList = dataList;
			else if (obj is PgpCompressedData compressedData)
				message = compressedData;
			else
				encryptedDataList = (PgpEncryptedDataList)objFactory.NextPgpObject();

			// If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
			if (encryptedDataList == null && message == null)
				throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

			using (CompositeDisposable disposables = new CompositeDisposable())
			{
				// decrypt
				PgpPrivateKey privateKey = null;
				PgpPublicKeyEncryptedData pbe = null;
				if (encryptedDataList != null)
				{
					foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in
							 encryptedDataList.GetEncryptedDataObjects())
					{
						privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

						if (privateKey != null)
						{
							pbe = publicKeyEncryptedData;
							break;
						}
					}

					if (privateKey == null)
						throw new ArgumentException("Secret key for message not found.");

					Stream clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
					PgpObjectFactory plainFact = new PgpObjectFactory(clear);

					message = plainFact.NextPgpObject();

					if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
					{
						PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
						var keyIdToVerify = pgpOnePassSignature.KeyId;

						var verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
							out PgpPublicKey _);
						if (verified == false)
							throw new PgpException("Failed to verify file.");

						message = plainFact.NextPgpObject();
					}
					else if (message is PgpSignatureList pgpSignatureList)
					{
						PgpSignature pgpSignature = pgpSignatureList[0];
						var keyIdToVerify = pgpSignature.KeyId;

						var verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
							out PgpPublicKey _);
						if (verified == false)
							throw new PgpException("Failed to verify file.");

						message = plainFact.NextPgpObject();
					}
					else if (!(message is PgpCompressedData))
						throw new PgpException("File was not signed.");
				}

				if (message is PgpCompressedData cData)
				{
                    Stream compDataIn = cData.GetDataStream().DisposeWith(disposables);
                    PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
                    message = objectFactory.NextPgpObject();

                    long? keyIdToVerify = null;

                    if (message is PgpSignatureList pgpSignatureList)
                    {
                        keyIdToVerify = pgpSignatureList[0].KeyId;
                    }
                    else if (message is PgpOnePassSignatureList pgpOnePassSignatureList)
                    {
                        PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
                        keyIdToVerify = pgpOnePassSignature.KeyId;
                    }

                    if (keyIdToVerify.HasValue)
                    {
                        var verified = Utilities.FindPublicKey(keyIdToVerify.Value, EncryptionKeys.VerificationKeys,
                            out PgpPublicKey _);
                        if (verified == false)
                            throw new PgpException("Failed to verify file.");

                        message = objectFactory.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        StreamHelper.PipeAll(unc, outputStream);
                    }
                    else
                    {
                        throw new PgpException("File was not signed.");
                    }
                }
				else if (message is PgpLiteralData literalData)
				{
					Stream unc = literalData.GetInputStream();
					StreamHelper.PipeAll(unc, outputStream);

					if (pbe.IsIntegrityProtected())
					{
						if (!pbe.Verify())
						{
							throw new PgpException("Message failed integrity check.");
						}
					}
				}
				else
					throw new PgpException("File was not signed.");
			}
		}

		#endregion DecryptAndVerify

		#region VerifyAsync

		private Task<VerificationResult> VerifyAsync(Stream inputStream, bool throwIfEncrypted = false)
		{
			bool verified = false;
			StringBuilder contentStringBuilder = new StringBuilder();

			Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
			PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
			PgpObject pgpObject = factory.NextPgpObject();

			if (pgpObject is PgpCompressedData)
			{
				PgpPublicKeyEncryptedData publicKeyEncryptedData = Utilities.ExtractPublicKeyEncryptedData(encodedFile);

				// Verify against public key ID and that of any sub keys
				var keyIdToVerify = publicKeyEncryptedData.KeyId;
				verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
					out PgpPublicKey _);
			}
			else if (pgpObject is PgpEncryptedDataList dataList)
			{
				if (throwIfEncrypted)
				{
					throw new ArgumentException("Input is encrypted. Decrypt the input first.");
				}
				PgpPublicKeyEncryptedData publicKeyEncryptedData = Utilities.ExtractPublicKey(dataList);
				var keyIdToVerify = publicKeyEncryptedData.KeyId;
				// If we encounter an encrypted packet, verify with the encryption keys used instead
				// TODO does this even make sense? maybe throw exception instead, or try to decrypt first
				verified = Utilities.FindPublicKeyInKeyRings(keyIdToVerify, EncryptionKeys.PublicKeyRings.Select(keyRing => keyRing.PgpPublicKeyRing), out PgpPublicKey _);
			}
			else if (pgpObject is PgpOnePassSignatureList onePassSignatureList)
			{
				PgpOnePassSignature pgpOnePassSignature = onePassSignatureList[0];
				PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
				Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

				// Verify against public key ID and that of any sub keys
				var keyIdToVerify = pgpOnePassSignature.KeyId;
				if (Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
					    out PgpPublicKey validationKey))
				{
					pgpOnePassSignature.InitVerify(validationKey);

					int ch;
					while ((ch = pgpLiteralStream.ReadByte()) >= 0)
					{
						pgpOnePassSignature.Update((byte)ch);
                        contentStringBuilder.Append((char)ch);
                    }

					PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

					for (int i = 0; i < pgpSignatureList.Count; i++)
					{
						PgpSignature pgpSignature = pgpSignatureList[i];

						if (pgpOnePassSignature.Verify(pgpSignature))
						{
							verified = true;
							break;
						}
					}
				}
			}
			else if (pgpObject is PgpSignatureList signatureList)
			{
				PgpSignature pgpSignature = signatureList[0];
				PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
				Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

				// Verify against public key ID and that of any sub keys
				if (Utilities.FindPublicKey(pgpSignature.KeyId, EncryptionKeys.VerificationKeys,
					    out PgpPublicKey publicKey))
				{
					foreach (PgpSignature _ in publicKey.GetSignatures())
					{
						if (!verified)
						{
							pgpSignature.InitVerify(publicKey);

							int ch;
							while ((ch = pgpLiteralStream.ReadByte()) >= 0)
							{
								pgpSignature.Update((byte)ch);
                                contentStringBuilder.Append((char)ch);
                            }

							verified = pgpSignature.Verify();
						}
						else
						{
							break;
						}
					}
				}
			}
			else
				throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

			return Task.FromResult(new VerificationResult(verified, contentStringBuilder.ToString()));
		}

		#endregion VerifyAsync

		#region Verify

		private VerificationResult Verify(Stream inputStream, bool throwIfEncrypted = false)
		{
			bool verified = false;
            StringBuilder contentStringBuilder = new StringBuilder();

            ArmoredInputStream encodedFile = new ArmoredInputStream(inputStream);
			PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
			PgpObject pgpObject = factory.NextPgpObject();

			if (pgpObject is PgpCompressedData compressedData)
			{
				PgpObjectFactory pgpCompressedFactory = new PgpObjectFactory(compressedData.GetDataStream());

				PgpOnePassSignatureList pgpOnePassSignatureList =
					(PgpOnePassSignatureList)pgpCompressedFactory.NextPgpObject();
				PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[0];
				PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
				Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

				var keyIdToVerify = pgpOnePassSignature.KeyId;

				// Verify against public key ID and that of any sub keys
				if (!Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
					    out PgpPublicKey publicKey)) return new VerificationResult(false, string.Empty);
				foreach (PgpSignature _ in publicKey.GetSignatures())
				{
					if (!verified)
					{
						pgpOnePassSignature.InitVerify(publicKey);

						int ch;
						while ((ch = pgpLiteralStream.ReadByte()) >= 0)
						{
							pgpOnePassSignature.Update((byte)ch);
						}

						PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

						for (int i = 0; i < pgpSignatureList.Count; i++)
						{
							PgpSignature pgpSignature = pgpSignatureList[i];

							if (pgpOnePassSignature.Verify(pgpSignature))
							{
								verified = true;
								break;
							}
						}
					}
					else
					{
						break;
					}
				}
			}
			else if (pgpObject is PgpEncryptedDataList encryptedDataList)
			{
				if (throwIfEncrypted)
				{
					throw new ArgumentException("Input is encrypted. Decrypt the input first.");
				}

				PgpPublicKeyEncryptedData publicKeyEncryptedData = Utilities.ExtractPublicKey(encryptedDataList);
				var keyIdToVerify = publicKeyEncryptedData.KeyId;

				// Verify against public key ID and that of any sub keys

				// If we encounter an encrypted packet, verify the encryption key used instead
				// TODO does this even make sense? maybe throw exception instead, or try to decrypt first
				if (Utilities.FindPublicKeyInKeyRings(keyIdToVerify, EncryptionKeys.PublicKeyRings.Select(keyRing => keyRing.PgpPublicKeyRing), out PgpPublicKey _))
				{
					verified = true;
				}
			}
			else if (pgpObject is PgpOnePassSignatureList onePassSignatureList)
			{
				PgpOnePassSignature pgpOnePassSignature = onePassSignatureList[0];
				PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
				Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

				// Verify against public key ID and that of any sub keys
				if (Utilities.FindPublicKey(pgpOnePassSignature.KeyId, EncryptionKeys.VerificationKeys,
					    out PgpPublicKey publicKey))
				{
					pgpOnePassSignature.InitVerify(publicKey);

					int ch;
					while ((ch = pgpLiteralStream.ReadByte()) >= 0)
					{
						pgpOnePassSignature.Update((byte)ch);
                        contentStringBuilder.Append((char)ch);
                    }

					PgpSignatureList pgpSignatureList = (PgpSignatureList)factory.NextPgpObject();

					for (int i = 0; i < pgpSignatureList.Count; i++)
					{
						PgpSignature pgpSignature = pgpSignatureList[i];

						if (pgpOnePassSignature.Verify(pgpSignature))
						{
							verified = true;
							break;
						}
					}
				}
			}
			else if (pgpObject is PgpSignatureList signatureList)
			{
				PgpSignature pgpSignature = signatureList[0];
				PgpLiteralData pgpLiteralData = (PgpLiteralData)factory.NextPgpObject();
				Stream pgpLiteralStream = pgpLiteralData.GetInputStream();

				// Verify against public key ID and that of any sub keys
				if (Utilities.FindPublicKey(pgpSignature.KeyId, EncryptionKeys.VerificationKeys,
					    out PgpPublicKey publicKey))
				{
					foreach (PgpSignature _ in publicKey.GetSignatures())
					{
						if (!verified)
						{
							pgpSignature.InitVerify(publicKey);

							int ch;
							while ((ch = pgpLiteralStream.ReadByte()) >= 0)
							{
								pgpSignature.Update((byte)ch);
                                contentStringBuilder.Append((char)ch);
                            }

							verified = pgpSignature.Verify();
						}
						else
						{
							break;
						}
					}
				}
			}
			else
				throw new PgpException("Message is not a encrypted and signed file or simple signed file.");

			return new VerificationResult(verified, contentStringBuilder.ToString());
		}

		#endregion Verify

		#region VerifyClearAsync

		// https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        private async Task<bool> VerifyClearAsync(Stream inputStream, Stream outputStream=null)
		{
			bool verified;

			using (MemoryStream outStream = new MemoryStream())
			{
				using (ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream))
				{
					MemoryStream lineOut = new MemoryStream();
					byte[] lineSep = LineSeparator;
					int lookAhead = ReadInputLine(lineOut, armoredInputStream);

					// Read past message to signature and store message in stream
					if (lookAhead != -1 && armoredInputStream.IsClearText())
					{
						byte[] line = lineOut.ToArray();
						await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
						await outStream.WriteAsync(lineSep, 0, lineSep.Length);

						while (lookAhead != -1 && armoredInputStream.IsClearText())
						{
							lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

							line = lineOut.ToArray();
							await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
							await outStream.WriteAsync(lineSep, 0, lineSep.Length);
						}
					}
					else if (lookAhead != -1)
					{
						byte[] line = lineOut.ToArray();
						await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
						await outStream.WriteAsync(lineSep, 0, lineSep.Length);
					}

					// Get public key from correctly positioned stream and initialise for verification
					PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
					PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
					PgpSignature pgpSignature = pgpSignatureList[0];

					pgpSignature.InitVerify(EncryptionKeys.VerificationKeys.First());

					// Read through message again and calculate signature
					outStream.Position = 0;
					lookAhead = ReadInputLine(lineOut, outStream);

					ProcessLine(pgpSignature, lineOut.ToArray());

					while (lookAhead != -1)
					{
						lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

						pgpSignature.Update((byte)'\r');
						pgpSignature.Update((byte)'\n');

						ProcessLine(pgpSignature, lineOut.ToArray());
					}

					verified = pgpSignature.Verify();
				}

                // Copy the message to the outputStream, if supplied
                if (outputStream != null)
                {
                    outStream.Position = 0;
                    await outStream.CopyToAsync(outputStream);
                }
			}

			return verified;
		}

		#endregion VerifyClearAsync

		#region VerifyClear

		// https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        private bool VerifyClear(Stream inputStream, Stream outputStream=null)
		{
			bool verified;

			using (MemoryStream outStream = new MemoryStream())
			{

				using (ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream))
				{
					MemoryStream lineOut = new MemoryStream();
					byte[] lineSep = LineSeparator;
					int lookAhead = ReadInputLine(lineOut, armoredInputStream);

					// Read past message to signature and store message in stream
					if (lookAhead != -1 && armoredInputStream.IsClearText())
					{
						byte[] line = lineOut.ToArray();
						outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
						outStream.Write(lineSep, 0, lineSep.Length);

						while (lookAhead != -1 && armoredInputStream.IsClearText())
						{
							lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

							line = lineOut.ToArray();
							outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
							outStream.Write(lineSep, 0, lineSep.Length);
						}
					}
					else if (lookAhead != -1)
					{
						byte[] line = lineOut.ToArray();
						outStream.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
						outStream.Write(lineSep, 0, lineSep.Length);
					}

					// Get public key from correctly positioned stream and initialise for verification
					PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
					PgpSignatureList pgpSignatureList = (PgpSignatureList)pgpObjectFactory.NextPgpObject();
					PgpSignature pgpSignature = pgpSignatureList[0];

					pgpSignature.InitVerify(EncryptionKeys.VerificationKeys.First());

					// Read through message again and calculate signature
					outStream.Position = 0;
					lookAhead = ReadInputLine(lineOut, outStream);

					ProcessLine(pgpSignature, lineOut.ToArray());

					while (lookAhead != -1)
					{
						lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

						pgpSignature.Update((byte)'\r');
						pgpSignature.Update((byte)'\n');

						ProcessLine(pgpSignature, lineOut.ToArray());
					}

					verified = pgpSignature.Verify();

                    // Copy the message to the outputStream, if supplied
                    if (outputStream != null)
                    {
                        outStream.Position = 0;
                        outStream.CopyTo(outputStream);
                    }
				}
			}

			return verified;
		}

		#endregion VerifyClear

		#region WriteOutputAndSign

		private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, FileStream inputFileStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = await inputFileStream.ReadAsync(buf, 0, buf.Length)) > 0)
			{
				await literalOut.WriteAsync(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFileStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = inputFileStream.Read(buf, 0, buf.Length)) > 0)
			{
				literalOut.Write(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, Stream inputStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
			{
				await literalOut.WriteAsync(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, Stream inputStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
			{
				literalOut.Write(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		#endregion WriteOutputAndSign

		#region ChainEncryptedOut

		private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
		{
			var encryptedDataGenerator =
				new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

			foreach (PgpPublicKeyRingWithPreferredKey publicKeyRing in EncryptionKeys.PublicKeyRings)
			{
				PgpPublicKey publicKey = publicKeyRing.PreferredEncryptionKey ?? publicKeyRing.DefaultEncryptionKey;
				encryptedDataGenerator.AddMethod(publicKey);
			}

			return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
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

		private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file.Name, file.Length,
				DateTime.UtcNow);
		}

		#endregion ChainLiteralOut

		#region ChainLiteralStreamOut

		private Stream ChainLiteralStreamOut(Stream compressedOut, Stream inputStream, string name)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length,
				DateTime.UtcNow);
		}

		#endregion ChainLiteralStreamOut

		#region InitSignatureGenerator

		private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
		{
			PublicKeyAlgorithmTag tag = EncryptionKeys.SigningSecretKey.PublicKey.Algorithm;
			PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
			pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, EncryptionKeys.SigningPrivateKey);
			foreach (string userId in EncryptionKeys.SigningSecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.SetSignerUserId(false, userId);
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
				subPacketGenerator.SetSignerUserId(false, userId);
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

		private void ExportKeyPair(
			Stream secretOut,
			Stream publicOut,
			PgpSecretKey secretKey,
			bool armor,
			bool emitVersion)
		{
			if (secretOut == null)
				throw new ArgumentException("secretOut");
			if (publicOut == null)
				throw new ArgumentException("publicOut");

			ArmoredOutputStream secretOutArmored;
			if (armor)
			{
				secretOutArmored = new ArmoredOutputStream(secretOut);
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

			secretKey.Encode(secretOut);

			secretOutArmored?.Dispose();

			ArmoredOutputStream publicOutArmored;
			if (armor)
			{
				publicOutArmored = new ArmoredOutputStream(publicOut);
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

			PgpPublicKey key = secretKey.PublicKey;

			key.Encode(publicOut);

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

		# endregion Misc Utilities

		#endregion Private helpers
		
	}
}
