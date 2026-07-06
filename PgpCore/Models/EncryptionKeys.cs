using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

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
		public PgpPublicKey MasterKey => _masterKey.Value;
		public PgpPrivateKey PrivateKey => SigningPrivateKey;
		public PgpSecretKey SecretKey => SigningSecretKey;
		public PgpSecretKeyRingBundle SecretKeys => _secretKeys.Value;

		/// <summary>
		/// An optional symmetric key used for symmetric encryption/decryption.
		/// Set this property to enable symmetric encryption alongside or instead of asymmetric PGP encryption.
		/// </summary>
		public byte[] SymmetricKey { get; set; }

		#endregion Instance Members (Public)

		#region Instance Members (Private)

		private readonly byte[] _passPhrase;

		// Set only when the keys were assembled from multiple private-key sources that may each
		// carry a different passphrase. Maps a secret key id to the passphrase for its source.
		private readonly Func<long, byte[]> _passPhraseResolver;

		private Lazy<IEnumerable<PgpPublicKey>> _encryptKeys;
		private Lazy<IEnumerable<PgpPublicKey>> _verificationKeys;
		private Lazy<PgpPublicKey> _masterKey;
		private Lazy<PgpPrivateKey> _signingPrivateKey;
		private Lazy<PgpSecretKey> _signingSecretKey;
		private Lazy<PgpSecretKeyRingBundle> _secretKeys;
		private Lazy<IEnumerable<PgpPublicKeyRingWithPreferredKey>> _publicKeyRingsWithPreferredKey;

		#endregion Instance Members (Private)

		#region Constructors

		#region Public + Private Key Constructors

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
			: this(publicKey, privateKey,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKey">The key used to encrypt the data</param>
		/// <param name="privateKey">The key used to sign the data.</param>
		/// <param name="rawPassPhrase">The raw passphrase bytes required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(string publicKey, string privateKey, byte[] rawPassPhrase)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new ArgumentException($"{nameof(publicKey)} cannot be null or empty.", nameof(publicKey));
			if (string.IsNullOrEmpty(privateKey))
				throw new ArgumentException($"{nameof(privateKey)} cannot be null or empty.", nameof(privateKey));
			if (rawPassPhrase == null)
				throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			
			List<PgpPublicKeyRing> keyRings;
			using (Stream publicKeyStream = publicKey.GetStream())
				keyRings = Utilities.ReadAllKeyRings(publicKeyStream).ToList();

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
			{
				using (Stream privateKeyStream = privateKey.GetStream())
					return Utilities.ReadSecretKeyRingBundle(privateKeyStream);
			});

			_passPhrase = rawPassPhrase;
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
			: this(publicKeyFile, privateKeyFile,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
		/// The data is encrypted with the recipients public key and signed with your private key.
		/// </summary>
		/// <param name="publicKeyFile">The key used to encrypt the data</param>
		/// <param name="privateKeyFile">The key used to sign the data.</param>
		/// <param name="rawPassPhrase">The raw passphrase bytes required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(FileInfo publicKeyFile, FileInfo privateKeyFile, byte[] rawPassPhrase)
		{
			if (publicKeyFile == null)
				throw new ArgumentNullException(nameof(publicKeyFile));
			if (privateKeyFile == null)
				throw new ArgumentNullException(nameof(privateKeyFile));
			if (rawPassPhrase == null)
				throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");

			if (!publicKeyFile.Exists)
				throw new FileNotFoundException($"Public Key file [{publicKeyFile.FullName}] does not exist.");
			if (!privateKeyFile.Exists)
				throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");
			
			List<PgpPublicKeyRing> keyRings;
			using (Stream publicKeyStream = publicKeyFile.OpenRead())
				keyRings = Utilities.ReadAllKeyRings(publicKeyStream).ToList();

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
			{
				using (Stream privateKeyStream = privateKeyFile.OpenRead())
					return Utilities.ReadSecretKeyRingBundle(privateKeyStream);
			});
			_passPhrase = rawPassPhrase;
			InitializeKeys(keyRings);
		}

		#endregion Public + Private Key Constructors

		#region Multiple Public + Private Key Constructors

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
			: this(publicKeys, privateKey,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
		/// The data is encrypted with the recipients public key(s) and signed with your private key.
		/// </summary>
		/// <param name="publicKeys">The key(s) used to encrypt the data</param>
		/// <param name="privateKey">The key used to sign the data.</param>
		/// <param name="rawPassPhrase">The raw passphrase bytes required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(IEnumerable<string> publicKeys, string privateKey, byte[] rawPassPhrase)
		{
			if (string.IsNullOrEmpty(privateKey))
				throw new ArgumentException($"{nameof(privateKey)} cannot be null or empty.", nameof(privateKey));
			if (rawPassPhrase == null)
				throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			
			string[] publicKeyStrings = publicKeys.ToArray(); // Avoid multiple enumeration
			foreach (string publicKey in publicKeyStrings)
			{
				if (string.IsNullOrEmpty(publicKey))
					throw new ArgumentException($"{nameof(publicKey)} cannot be null or empty.", nameof(publicKey));
			}
				
			List<PgpPublicKeyRing> keyRings = new List<PgpPublicKeyRing>();
			foreach (string publicKey in publicKeyStrings)
			{
				using (Stream publicKeyStream = publicKey.GetStream())
					keyRings.AddRange(Utilities.ReadAllKeyRings(publicKeyStream));
			}

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
			{
				using (Stream privateKeyStream = privateKey.GetStream())
					return Utilities.ReadSecretKeyRingBundle(privateKeyStream);
			});
			_passPhrase = rawPassPhrase;
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
			: this(publicKeyFiles, privateKeyFile,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
		/// The data is encrypted with the recipients public key(s) and signed with your private key.
		/// </summary>
		/// <param name="publicKeyFiles">The key(s) used to encrypt the data</param>
		/// <param name="privateKeyFile">The key used to sign the data.</param>
		/// <param name="rawPassPhrase">The raw passphrase bytes required to access the private key</param>
		/// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
		public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles, FileInfo privateKeyFile, byte[] rawPassPhrase)
		{
			// Avoid multiple enumerations of 'publicKeyFilePaths'
			FileInfo[] publicKeys = publicKeyFiles.ToArray();

			if (privateKeyFile == null)
				throw new ArgumentNullException(nameof(privateKeyFile));
			if (rawPassPhrase == null)
				throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");

			if (!privateKeyFile.Exists)
				throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");

			foreach (FileInfo publicKeyFile in publicKeys)
			{
				if (publicKeyFile == null)
					throw new ArgumentNullException(nameof(publicKeyFile));
				if (!File.Exists(publicKeyFile.FullName))
					throw new FileNotFoundException($"Input file [{publicKeyFile.FullName}] does not exist.");
			}
			
			List<PgpPublicKeyRing> keyRings = new List<PgpPublicKeyRing>();
			foreach (FileInfo publicKeyFile in publicKeys)
			{
				using (Stream publicKeyStream = publicKeyFile.OpenRead())
					keyRings.AddRange(Utilities.ReadAllKeyRings(publicKeyStream));
			}

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
			{
				using (Stream privateKeyStream = privateKeyFile.OpenRead())
					return Utilities.ReadSecretKeyRingBundle(privateKeyStream);
			});
			_passPhrase = rawPassPhrase;
			InitializeKeys(keyRings);
		}

		#endregion Multiple Public + Private Key Constructors

		#region Private Key Only Constructors

		public EncryptionKeys(string privateKey, string passPhrase)
			: this(privateKey,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		public EncryptionKeys(string privateKey, byte[] rawPassPhrase)
		{
			if (string.IsNullOrEmpty(privateKey))
				throw new ArgumentException($"{nameof(privateKey)} cannot be null or empty.", nameof(privateKey));

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
			{
				using (Stream privateKeyStream = privateKey.GetStream())
					return Utilities.ReadSecretKeyRingBundle(privateKeyStream);
			});
			_passPhrase = rawPassPhrase ?? throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			InitializeKeys();
		}

		public EncryptionKeys(FileInfo privateKeyFile, string passPhrase)
			: this(privateKeyFile,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		public EncryptionKeys(FileInfo privateKeyFile, byte[] rawPassPhrase)
		{
			if (privateKeyFile is null)
				throw new ArgumentNullException(nameof(privateKeyFile));

			if (!privateKeyFile.Exists)
				throw new FileNotFoundException($"Private Key file [{privateKeyFile.FullName}] does not exist.");

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
			{
				using (Stream privateKeyStream = privateKeyFile.OpenRead())
					return Utilities.ReadSecretKeyRingBundle(privateKeyStream);
			});
			_passPhrase = rawPassPhrase ?? throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			InitializeKeys();
		}

		#endregion Private Key Only Constructors

		#region Stream Constructors (Public + Private)

		public EncryptionKeys(Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
			: this(publicKeyStream, privateKeyStream,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		public EncryptionKeys(Stream publicKeyStream, Stream privateKeyStream, byte[] rawPassPhrase)
		{
			if (publicKeyStream == null)
				throw new ArgumentNullException(nameof(publicKeyStream));
			if (privateKeyStream == null)
				throw new ArgumentNullException(nameof(privateKeyStream));
			if (rawPassPhrase == null)
				throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			
			var keyRings = Utilities.ReadAllKeyRings(publicKeyStream);

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyStream));
			_passPhrase = rawPassPhrase;
			InitializeKeys(keyRings);
		}

		#endregion Stream Constructors (Public + Private)

		#region Stream Constructors (Private Only)

		public EncryptionKeys(Stream privateKeyStream, string passPhrase)
			: this(privateKeyStream,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		public EncryptionKeys(Stream privateKeyStream, byte[] rawPassPhrase)
		{
			if (privateKeyStream == null)
				throw new ArgumentNullException(nameof(privateKeyStream));
			
			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyStream));
			_passPhrase = rawPassPhrase ?? throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			InitializeKeys();
		}

		#endregion Stream Constructors (Private Only)

		#region Stream Constructors (Multiple Public + Private)

		public EncryptionKeys(IEnumerable<Stream> publicKeyStreams, Stream privateKeyStream, string passPhrase)
			: this(publicKeyStreams, privateKeyStream,
				Encoding.UTF8.GetBytes(passPhrase ?? throw new ArgumentNullException(nameof(passPhrase), "Invalid Pass Phrase.")))
		{
		}
		
		public EncryptionKeys(IEnumerable<Stream> publicKeyStreams, Stream privateKeyStream, byte[] rawPassPhrase)
		{
			// Avoid multiple enumerations of 'publicKeyFilePaths'
			Stream[] publicKeyStreamArray = publicKeyStreams.ToArray();

			if (privateKeyStream == null)
				throw new ArgumentNullException(nameof(privateKeyStream));
			if (rawPassPhrase == null)
				throw new ArgumentNullException(nameof(rawPassPhrase), "Invalid Pass Phrase.");
			foreach (Stream publicKeyStream in publicKeyStreamArray)
			{
				if (publicKeyStream == null)
					throw new ArgumentNullException(nameof(publicKeyStream));
			}
			
			var keyRings = Utilities.ReadAllKeyRings(publicKeyStreamArray);

			_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => Utilities.ReadSecretKeyRingBundle(privateKeyStream));
			_passPhrase = rawPassPhrase;
			InitializeKeys(keyRings);
		}

		#endregion Stream Constructors (Multiple Public + Private)

		#region Builder Constructor

		/// <summary>
		/// Assembles keys from pre-parsed material. Used by <see cref="EncryptionKeysBuilder"/> to
		/// support multiple public and private key sources (each private source potentially carrying
		/// its own passphrase) and an explicit preferred encryption key.
		/// </summary>
		internal EncryptionKeys(
			IReadOnlyCollection<PgpPublicKeyRing> publicKeyRings,
			PgpSecretKeyRingBundle secretKeys,
			Func<long, byte[]> passPhraseResolver,
			byte[] symmetricKey,
			long? preferredEncryptionKeyId)
		{
			SymmetricKey = symmetricKey;
			_passPhraseResolver = passPhraseResolver;

			if (secretKeys != null)
				_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => secretKeys);

			if (publicKeyRings != null && publicKeyRings.Count > 0)
				InitializeKeys(publicKeyRings);
			else
				InitializeKeys();

			if (preferredEncryptionKeyId.HasValue && publicKeyRings != null && publicKeyRings.Count > 0)
				UseEncryptionKey(preferredEncryptionKeyId.Value);
		}

		#endregion Builder Constructor

		#region Symmetric Key Only Constructor

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class that is to be used for symmetric encryption/decryption exclusively.
		/// The data is encrypted with the passed <paramref name="symmetricKey"/>.
		/// </summary>
		/// <param name="symmetricKey">The key used to encrypt/decrypt the data</param>
		public EncryptionKeys(byte[] symmetricKey)
		{
			if (symmetricKey == null || symmetricKey.Length == 0)
			{
				throw new ArgumentException($"{nameof(symmetricKey)} cannot be null or empty.", nameof(symmetricKey));
			}
			
			SymmetricKey = symmetricKey;

			try
			{
				InitializeKeys(Array.Empty<PgpPublicKeyRing>(), allowEmptyPublicKeys: true);
			}
			catch (Exception ex) when (!(ex is PgpCoreException))
			{
				throw new InvalidKeyMaterialException("Error initializing keys.", ex);
			}
		}

		#endregion Symmetric Key Only Constructor

		#region Public Key Only Constructors

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// The data is encrypted with the recipients public key.
		/// </summary>
		/// <param name="publicKey">The key used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found.</exception>
		public EncryptionKeys(string publicKey)
		{
			if (string.IsNullOrEmpty(publicKey))
				throw new ArgumentException($"{nameof(publicKey)} cannot be null or empty.", nameof(publicKey));
			
            try
            {
                List<PgpPublicKeyRing> keyRings;
                using (Stream publicKeyStream = publicKey.GetStream())
                    keyRings = Utilities.ReadAllKeyRings(publicKeyStream).ToList();

                InitializeKeys(keyRings);
            }
            catch (Exception ex) when (!(ex is PgpCoreException))
            {
                throw new InvalidKeyMaterialException($"Error reading public key.", ex);
            }
        }

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// The data is encrypted with the recipients public key.
		/// </summary>
		/// <param name="publicKeyFile">The key used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found.</exception>
		public EncryptionKeys(FileInfo publicKeyFile)
		{
			if (publicKeyFile == null)
				throw new ArgumentNullException(nameof(publicKeyFile));

			if (!publicKeyFile.Exists)
				throw new FileNotFoundException($"Public Key file [{publicKeyFile.FullName}] does not exist.");
			
			try
			{
				List<PgpPublicKeyRing> keyRings;
				using (Stream publicKeyStream = publicKeyFile.OpenRead())
					keyRings = Utilities.ReadAllKeyRings(publicKeyStream).ToList();

				InitializeKeys(keyRings);
			}
			catch (Exception ex) when (!(ex is PgpCoreException))
			{
				throw new InvalidKeyMaterialException($"Error reading public key file [{publicKeyFile.FullName}].", ex);
			}
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// The data is encrypted with the recipients public keys.
		/// </summary>
		/// <param name="publicKeys">The keys used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found.</exception>
		public EncryptionKeys(IEnumerable<string> publicKeys)
		{
			string[] publicKeyStrings = publicKeys.ToArray();
			foreach (string publicKey in publicKeyStrings)
			{
				if (string.IsNullOrEmpty(publicKey))
					throw new ArgumentException($"{nameof(publicKey)} cannot be null or empty.", nameof(publicKey));
			}

			try
			{
                List<PgpPublicKeyRing> keyRings = new List<PgpPublicKeyRing>();
                foreach (string publicKey in publicKeyStrings)
                {
                    using (Stream publicKeyStream = publicKey.GetStream())
                        keyRings.AddRange(Utilities.ReadAllKeyRings(publicKeyStream));
                }

                InitializeKeys(keyRings);
            }
			catch (Exception ex) when (!(ex is PgpCoreException))
            {
                throw new InvalidKeyMaterialException("Error reading public keys.", ex);
            }
		}

		/// <summary>
		/// Initializes a new instance of the EncryptionKeys class.
		/// The data is encrypted with the recipients public keys.
		/// </summary>
		/// <param name="publicKeyFiles">The keys used to encrypt the data</param>
		/// <exception cref="ArgumentException">Public key not found.</exception>
		public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles)
		{
			// Avoid multiple enumerations of 'publicKeyFiles'
			FileInfo[] publicKeys = publicKeyFiles.ToArray();

			foreach (FileInfo publicKeyFile in publicKeys)
			{
				if (publicKeyFile is null)
					throw new ArgumentNullException(nameof(publicKeyFile));
				if (!publicKeyFile.Exists)
					throw new FileNotFoundException($"Input file [{publicKeyFile.FullName}] does not exist.");
			}

			try
			{
                List<PgpPublicKeyRing> keyRings = new List<PgpPublicKeyRing>();
                foreach (FileInfo publicKeyFile in publicKeys)
                {
                    using (Stream publicKeyStream = publicKeyFile.OpenRead())
                        keyRings.AddRange(Utilities.ReadAllKeyRings(publicKeyStream));
                }

                InitializeKeys(keyRings);
            }
			catch (Exception ex) when (!(ex is PgpCoreException))
            {
                throw new InvalidKeyMaterialException("Error reading public key files.", ex);
            }
		}

		public EncryptionKeys(Stream publicKeyStream)
		{
			if (publicKeyStream == null)
				throw new ArgumentNullException(nameof(publicKeyStream));
			
			try
			{
                var keyRings = Utilities.ReadAllKeyRings(publicKeyStream);

                InitializeKeys(keyRings);
            }
			catch (Exception ex) when (!(ex is PgpCoreException))
            {
                throw new InvalidKeyMaterialException("Error reading public key stream.", ex);
            }
		}

		public EncryptionKeys(IEnumerable<Stream> publicKeyStreams)
		{
			Stream[] publicKeys = publicKeyStreams.ToArray();

			foreach (Stream publicKey in publicKeys)
			{
				if (publicKey == null)
					throw new ArgumentNullException(nameof(publicKey));
			}

			try
			{
                var keyRings = Utilities.ReadAllKeyRings(publicKeys);

                InitializeKeys(keyRings);
            }
			catch (Exception ex) when (!(ex is PgpCoreException))
            {
                throw new InvalidKeyMaterialException("Error reading public key streams.", ex);
            }
		}

		#endregion Public Key Only Constructors

		#endregion Constructors

		#region Public Methods

		public PgpPrivateKey FindSecretKey(long keyId)
		{
			if (SecretKeys == null)
				throw new MissingKeyException("No private keys found. These should be provided in EncryptionKeys constructor.");

			PgpSecretKey pgpSecKey = SecretKeys.GetSecretKey(keyId);

			if (pgpSecKey == null)
				return null;

			return ExtractPrivateKey(pgpSecKey);
		}

		/// <summary>
		/// This method will try to find the key with the given keyId in a key ring and set it as the preferred key.
		/// If it cannot find the key, it will not change the preferred key.
		/// </summary>
		/// <param name="keyId">The keyId to find.</param>
		public void UseEncryptionKey(long keyId)
		{
			foreach (PgpPublicKeyRingWithPreferredKey publicKeyRing in PublicKeyRings)
			{
				publicKeyRing.UsePreferredEncryptionKey(keyId);
			}
		}

		#endregion Public Methods

		#region Private Key

		private PgpPrivateKey ReadPrivateKey(PgpSecretKey secretKey)
		{
			PgpPrivateKey privateKey = ExtractPrivateKey(secretKey);
			if (privateKey != null)
				return privateKey;

			throw new MissingKeyException("No private key found in secret key.");
		}

		private PgpPrivateKey ExtractPrivateKey(PgpSecretKey secretKey)
		{
			byte[] passPhrase = _passPhraseResolver != null ? _passPhraseResolver(secretKey.KeyId) : _passPhrase;
			try
			{
				return secretKey.ExtractPrivateKeyRaw(passPhrase);
			}
			catch (PgpException ex) when (ex.Message != null && ex.Message.IndexOf("checksum mismatch", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				throw new IncorrectPassphraseException(
					$"The passphrase supplied for private key [{secretKey.KeyId:X}] is incorrect.", ex);
			}
		}

		#endregion Private Key

		#region Helper Methods

		private void
			InitializeKeys(
				IEnumerable<PgpPublicKeyRing> publicKeyRings = null,
				bool allowEmptyPublicKeys = false) // Should only be run as the last step during construction!
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
				// Materialize once so stream-backed enumerables are not re-read per lazy, and so
				// unparseable key material fails here rather than on first use.
				PgpPublicKeyRing[] keyRings = publicKeyRings.ToArray();

				if (keyRings.Length == 0 && !allowEmptyPublicKeys)
					throw new InvalidKeyMaterialException("No PGP public keys found in the supplied key material.");

				_publicKeyRingsWithPreferredKey = new Lazy<IEnumerable<PgpPublicKeyRingWithPreferredKey>>(() => keyRings.Select(keyRing => new PgpPublicKeyRingWithPreferredKey(keyRing)).ToArray());
				_masterKey = new Lazy<PgpPublicKey>(() =>
					Utilities.FindMasterKey(keyRings.First()));
				_encryptKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
					keyRings.Select(Utilities.FindBestEncryptionKey).ToArray());
				// Include every key in each ring so signatures made by any subkey can be matched
				// by key id, while keeping the best verification key first for consumers that
				// only look at the primary key.
				_verificationKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
					keyRings.SelectMany(keyRing =>
					{
						PgpPublicKey bestKey = Utilities.FindBestVerificationKey(keyRing);
						return new[] { bestKey }.Concat(
							keyRing.GetPublicKeys().Cast<PgpPublicKey>().Where(key => key.KeyId != bestKey.KeyId));
					}).ToArray());
			}

			if (_secretKeys != null)
			{
				_signingSecretKey = new Lazy<PgpSecretKey>(() => Utilities.FindBestSigningKey(SecretKeys));
				if (SigningSecretKey != null)
					_signingPrivateKey = new Lazy<PgpPrivateKey>(() => ReadPrivateKey(SigningSecretKey));
			}
			else
			{
				_secretKeys = new Lazy<PgpSecretKeyRingBundle>(() => null);
			}
		}

		#endregion
	}
}