using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PgpCore
{
	public class EncryptionKeys : IEncryptionKeys
	{
		#region Instance Members (Public)

		public IEnumerable<PgpPublicKeyRingWithPreferredKey> PublicKeyRings => _publicKeyRingsWithPreferredKey.Value;
		public IEnumerable<PgpPublicKey> EncryptKeys => _encryptKeys.Value;
		public IEnumerable<PgpPublicKey> VerificationKeys => _verificationKeys.Value;
		public PgpPrivateKey SigningPrivateKey => _signingPrivateKey.Value;
		public PgpSecretKey SigningSecretKey => _signingSecretKey.Value;
		public IEnumerable<PgpPublicKey> PublicKeys => EncryptKeys;
		public PgpPublicKey MasterKey => _masterKey.Value;
		public PgpPublicKey PublicKey => EncryptKeys.FirstOrDefault();
		public PgpPrivateKey PrivateKey => SigningPrivateKey;
		public PgpSecretKey SecretKey => SigningSecretKey;
		public PgpSecretKeyRingBundle SecretKeys => _secretKeys.Value;

		#endregion Instance Members (Public)

		#region Instance Members (Private)

		private readonly string _passPhrase;

		private Lazy<IEnumerable<PgpPublicKey>> _encryptKeys;
		private Lazy<IEnumerable<PgpPublicKey>> _verificationKeys;
		private Lazy<PgpPublicKey> _masterKey;
		private Lazy<PgpPrivateKey> _signingPrivateKey;
		private Lazy<PgpSecretKey> _signingSecretKey;
		private Lazy<PgpSecretKeyRingBundle> _secretKeys;
		private Lazy<IEnumerable<PgpPublicKeyRingWithPreferredKey>> _publicKeyRingsWithPreferredKey;

		#endregion Instance Members (Private)

		#region Constructors

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKey">The key used to encrypt the data</param>
		/// <param name="privateKey">The key used to sign the data.</param>
		/// <param name="passPhrase">The password required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(string publicKey, string privateKey, string passPhrase)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new ArgumentException("PublicKeyFilePath");
			if (string.IsNullOrEmpty(privateKey))
				throw new ArgumentException("PrivateKeyFilePath");
			if (passPhrase == null)
				throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");

			var keyRings = Utilities.ReadAllKeyRings(publicKey.GetStream());

			_secretKeys =
				new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKey.GetStream()));

			_passPhrase = passPhrase;
			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKeyFile">The key used to encrypt the data</param>
		/// <param name="privateKeyFile">The key used to sign the data.</param>
		/// <param name="passPhrase">The password required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(FileInfo publicKeyFile, FileInfo privateKeyFile, string passPhrase)
		{
			if (publicKeyFile == null)
				throw new ArgumentException("PublicKeyFile");
			if (privateKeyFile == null)
				throw new ArgumentException("PrivateKeyFile");
			if (passPhrase == null)
				throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");

			if (!publicKeyFile.Exists)
				throw new FileNotFoundException($"Public Key file [{publicKeyFile.FullName}] does not exist.");
			if (!privateKeyFile.Exists)
				throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");

			var keyRings = Utilities.ReadAllKeyRings(publicKeyFile.OpenRead());

			_secretKeys =
				new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyFile.OpenRead()));
			_passPhrase = passPhrase;
			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
		/// The data is encrypted with the recipients public key(s) and signed with your private key.
		/// </summary>
		/// <param name="publicKeys">The key(s) used to encrypt the data</param>
		/// <param name="privateKey">The key used to sign the data.</param>
		/// <param name="passPhrase">The password required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(IEnumerable<string> publicKeys, string privateKey, string passPhrase)
		{
			if (string.IsNullOrEmpty(privateKey))
				throw new ArgumentException("PrivateKeyFilePath");
			if (passPhrase == null)
				throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");

			string[] publicKeyStrings = publicKeys.ToArray(); // Avoid multiple enumeration
			foreach (string publicKey in publicKeyStrings)
			{
				if (string.IsNullOrEmpty(publicKey))
					throw new ArgumentException(nameof(publicKey));
			}

			var keyRings = Utilities.ReadAllKeyRings(publicKeyStrings.Select(s => s.GetStream()));

			_secretKeys =
				new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKey.GetStream()));
			_passPhrase = passPhrase;
			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
		/// The data is encrypted with the recipients public key(s) and signed with your private key.
		/// </summary>
		/// <param name="publicKeyFiles">The key(s) used to encrypt the data</param>
		/// <param name="privateKeyFile">The key used to sign the data.</param>
		/// <param name="passPhrase">The password required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles, FileInfo privateKeyFile, string passPhrase)
		{
			// Avoid multiple enumerations of 'publicKeyFilePaths'
			FileInfo[] publicKeys = publicKeyFiles.ToArray();

			if (privateKeyFile == null)
				throw new ArgumentException("PrivateKeyFile");
			if (passPhrase == null)
				throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");

			if (!privateKeyFile.Exists)
				throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");

			FileInfo[] publicKeyFileInfos = publicKeys.ToArray(); // Avoid multiple enumeration

			foreach (FileInfo publicKeyFile in publicKeyFileInfos)
			{
				if (publicKeyFile == null)
					throw new ArgumentException(nameof(publicKeyFile.FullName));
				if (!File.Exists(publicKeyFile.FullName))
					throw new FileNotFoundException($"Input file [{publicKeyFile.FullName}] does not exist.");
			}

			var keyRings = Utilities.ReadAllKeyRings(publicKeys.Select(fileInfo => fileInfo.OpenRead()));

			_secretKeys =
				new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyFile.OpenRead()));
			_passPhrase = passPhrase;
			InitializeKeys(keyRings);
		}

		public EncryptionKeys(string privateKey, string passPhrase)
		{
			if (string.IsNullOrEmpty(privateKey))
				throw new ArgumentException("PrivateKey");

			_secretKeys =
				new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKey.GetStream()));
			_passPhrase = passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");
			InitializeKeys();
		}

		public EncryptionKeys(FileInfo privateKeyFile, string passPhrase)
		{
			if (privateKeyFile is null)
				throw new ArgumentException("PrivateKeyFile");

			if (!privateKeyFile.Exists)
				throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");

			_secretKeys =
				new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyFile.OpenRead()));
			_passPhrase = passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");
			InitializeKeys();
		}

		public EncryptionKeys(Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
		{
			if (publicKeyStream == null)
				throw new ArgumentException("PublicKeyStream");
			if (privateKeyStream == null)
				throw new ArgumentException("PrivateKeyStream");
			if (passPhrase == null)
				throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");

			var keyRings = Utilities.ReadAllKeyRings(publicKeyStream);

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyStream));
			_passPhrase = passPhrase;
			InitializeKeys(keyRings);
		}

		public EncryptionKeys(Stream privateKeyStream, string passPhrase)
		{
			if (privateKeyStream == null)
				throw new ArgumentException("PrivateKeyStream");

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyStream));
			_passPhrase = passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");
			InitializeKeys();
		}

		public EncryptionKeys(IEnumerable<Stream> publicKeyStreams, Stream privateKeyStream, string passPhrase)
		{
			// Avoid multiple enumerations of 'publicKeyFilePaths'
			Stream[] publicKeyStreamArray = publicKeyStreams.ToArray();

			if (privateKeyStream == null)
				throw new ArgumentException("PrivateKeyStream");
			if (passPhrase == null)
				throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.");
			foreach (Stream publicKeyStream in publicKeyStreamArray)
			{
				if (publicKeyStream == null)
					throw new ArgumentException("PublicKeyStream");
			}

			var keyRings = Utilities.ReadAllKeyRings(publicKeyStreamArray);

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyStream));
			_passPhrase = passPhrase;
			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKey">The key used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(string publicKey)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new ArgumentException("PublicKey");

			var keyRings = Utilities.ReadAllKeyRings(publicKey.GetStream());

			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKeyFile">The key used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(FileInfo publicKeyFile)
		{
			if (publicKeyFile == null)
				throw new ArgumentException("PublicKeyFilePath");

			if (!publicKeyFile.Exists)
				throw new FileNotFoundException($"Public Key file [{publicKeyFile.FullName}] does not exist.");

			var keyRings = Utilities.ReadAllKeyRings(publicKeyFile.OpenRead());

			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKeys">The keys used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(IEnumerable<string> publicKeys)
		{
			string[] publicKeyStrings = publicKeys.ToArray();
			foreach (string publicKey in publicKeyStrings)
			{
				if (string.IsNullOrEmpty(publicKey))
					throw new ArgumentException(nameof(publicKey));
			}

			var keyRings = Utilities.ReadAllKeyRings(publicKeyStrings.Select(s => s.GetStream()));

			InitializeKeys(keyRings);
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKeyFiles">The keys used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles)
		{
			// Avoid multiple enumerations of 'publicKeyFiles'
			FileInfo[] publicKeys = publicKeyFiles.ToArray();

			foreach (FileInfo publicKeyFile in publicKeys)
			{
				if (publicKeyFile is null)
					throw new ArgumentException(nameof(publicKeyFile));
				if (!publicKeyFile.Exists)
					throw new FileNotFoundException($"Input file [{publicKeyFile.FullName}] does not exist.");
			}

			var keyRings = Utilities.ReadAllKeyRings(publicKeys.Select(fileInfo => fileInfo.OpenRead()));

			InitializeKeys(keyRings);
		}

		public EncryptionKeys(Stream publicKeyStream)
		{
			if (publicKeyStream == null)
				throw new ArgumentException("PublicKeyStream");

			var keyRings = Utilities.ReadAllKeyRings(publicKeyStream);

			InitializeKeys(keyRings);
		}

		public EncryptionKeys(IEnumerable<Stream> publicKeyStreams)
		{
			Stream[] publicKeys = publicKeyStreams.ToArray();

			foreach (Stream publicKey in publicKeys)
			{
				if (publicKey == null)
					throw new ArgumentException("PublicKeyStream");
			}

			var keyRings = Utilities.ReadAllKeyRings(publicKeys);
			
			InitializeKeys(keyRings);
		}

		#endregion Constructors

		#region Public Methods

		public PgpPrivateKey FindSecretKey(long keyId)
		{
			PgpSecretKey pgpSecKey = SecretKeys.GetSecretKey(keyId);

			if (pgpSecKey == null)
				return null;

			return pgpSecKey.ExtractPrivateKey(_passPhrase.ToCharArray());
		}

		/// <summary>
		/// This method will try to find the key with the given keyId in a key ring and set it as the preferred key.
		/// If it cannot find the key, it will not change the preferred key.
		/// </summary>
		/// <param name="keyId">The keyId to find.</param>
		public void UseEncrytionKey(long keyId)
		{
			foreach (PgpPublicKeyRingWithPreferredKey publicKeyRing in PublicKeyRings)
			{
				publicKeyRing.UsePreferredEncryptionKey(keyId);
			}
		}

		#endregion Public Methods

		#region Private Key

		private PgpPrivateKey ReadPrivateKey(PgpSecretKey secretKey, string passPhrase)
		{
			PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(passPhrase.ToCharArray());
			if (privateKey != null)
				return privateKey;

			throw new ArgumentException("No private key found in secret key.");
		}

		#endregion Private Key

		#region Helper Methods

		private void
			InitializeKeys(
				IEnumerable<PgpPublicKeyRing> publicKeyRings =
					null) // Should only be run as the last step during construction!
		{
			if (publicKeyRings == null)
			{
				_masterKey = new Lazy<PgpPublicKey>(() => null);
				_encryptKeys = new Lazy<IEnumerable<PgpPublicKey>>(() => null);
				_verificationKeys = new Lazy<IEnumerable<PgpPublicKey>>(() => null);
				_publicKeyRingsWithPreferredKey = new Lazy<IEnumerable<PgpPublicKeyRingWithPreferredKey>>(() => null);
			}
			else
			{
				// Need to consume the stream into a list before it is closed (can happen because of lazy instantiation).
				_publicKeyRingsWithPreferredKey = new Lazy<IEnumerable<PgpPublicKeyRingWithPreferredKey>>(() => publicKeyRings.Select(keyRing => new PgpPublicKeyRingWithPreferredKey(keyRing)).ToArray());
				_masterKey = new Lazy<PgpPublicKey>(() =>
					Utilities.FindMasterKey(publicKeyRings.First()));
				_encryptKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
					publicKeyRings.Select(Utilities.FindBestEncryptionKey).ToArray());
				_verificationKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
					publicKeyRings.Select(Utilities.FindBestVerificationKey).ToArray());
			}

			if (_secretKeys != null)
			{
				_signingSecretKey = new Lazy<PgpSecretKey>(() => Utilities.FindBestSigningKey(SecretKeys));
				if (SigningSecretKey != null)
					_signingPrivateKey = new Lazy<PgpPrivateKey>(() => ReadPrivateKey(SigningSecretKey, _passPhrase));
			}
			else
			{
				_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => null);
			}
		}

		#endregion
	}
}