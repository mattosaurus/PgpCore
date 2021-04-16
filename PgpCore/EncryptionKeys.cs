using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public class EncryptionKeys : IEncryptionKeys
    {
        #region Instance Members (Public)
        public PgpPublicKey PublicKey => PublicKeys.FirstOrDefault();
        public IEnumerable<PgpPublicKey> PublicKeys => _publicKeys.Value;
        public PgpPrivateKey PrivateKey => _privateKey.Value;
        public PgpSecretKey SecretKey => _secretKey.Value;
        public PgpSecretKeyRingBundle SecretKeys => _secretKeys.Value;

        #endregion Instance Members (Public)

        #region Instance Members (Private)
        private readonly string _passPhrase;
        private Lazy<IEnumerable<PgpPublicKey>> _publicKeys;
        private Lazy<PgpPrivateKey> _privateKey;
        private Lazy<PgpSecretKey> _secretKey;
        private Lazy<PgpSecretKeyRingBundle> _secretKeys;

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
            if (String.IsNullOrEmpty(publicKey))
                throw new ArgumentException("PublicKeyFilePath");
            if (String.IsNullOrEmpty(privateKey))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKey.GetStream()) };
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKey.GetStream());
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKey.GetStream()))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
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
                throw new ArgumentNullException("Invalid Pass Phrase.");

            if (!publicKeyFile.Exists)
                throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFile.FullName));
            if (!privateKeyFile.Exists)
                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFile.FullName));

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyFile) };
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKeyFile);
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyFile.OpenRead()))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
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
            if (String.IsNullOrEmpty(privateKey))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            foreach (string publicKey in publicKeys)
            {
                if (String.IsNullOrEmpty(publicKey))
                    throw new ArgumentException(nameof(publicKey));
            }

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return publicKeys.Select(x => Utilities.ReadPublicKey(x.GetStream())).ToList();
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKey.GetStream());
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKey.GetStream()))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
        }

        /// <summary>
        /// Initializes a new instance of the EncryptionKeys class.
        /// Two or more keys are required to encrypt and sign data. Your private key and the recipients public key(s).
        /// The data is encrypted with the recipients public key(s) and signed with your private key.
        /// </summary>
        /// <param name="publicKeyFilePaths">The key(s) used to encrypt the data</param>
        /// <param name="privateKeyFilePath">The key used to sign the data.</param>
        /// <param name="passPhrase">The password required to access the private key</param>
        /// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
        public EncryptionKeys(IEnumerable<FileInfo> publicKeyFiles, FileInfo privateKeyFile, string passPhrase)
        {
            // Avoid multiple enumerations of 'publicKeyFilePaths'
            FileInfo[] publicKeys = publicKeyFiles.ToArray();

            if (privateKeyFile == null)
                throw new ArgumentException("PrivateKeyFile");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            if (!privateKeyFile.Exists)
                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFile.FullName));

            foreach (FileInfo publicKeyFile in publicKeys)
            {
                if (publicKeyFile == null)
                    throw new ArgumentException(nameof(publicKeyFile.FullName));
                if (!File.Exists(publicKeyFile.FullName))
                    throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", publicKeyFile.FullName));
            }

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return publicKeyFiles.Select(x => Utilities.ReadPublicKey(x)).ToList();
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKeyFile);
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyFile.OpenRead()))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
        }

        public EncryptionKeys(string privateKey, string passPhrase)
        {
            if (String.IsNullOrEmpty(privateKey))
                throw new ArgumentException("PrivateKey");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return null;
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKey.GetStream());
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKey.GetStream()))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
        }

        public EncryptionKeys(FileInfo privateKeyFile, string passPhrase)
        {
            if (privateKeyFile is null)
                throw new ArgumentException("PrivateKeyFile");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            if (!privateKeyFile.Exists)
                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFile.FullName));

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return null;
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKeyFile);
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyFile.OpenRead()))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
        }

        public EncryptionKeys(Stream publicKeyStream, Stream privateKeyStream, string passPhrase)
        {
            if (publicKeyStream == null)
                throw new ArgumentException("PublicKeyStream");
            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyStream");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyStream) };
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKeyStream);
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
        }

        public EncryptionKeys(Stream privateKeyStream, string passPhrase)
        {
            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyStream");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");

            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKeyStream);
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
        }

        public EncryptionKeys(IEnumerable<Stream> publicKeyStreams, Stream privateKeyStream, string passPhrase)
        {
            // Avoid multiple enumerations of 'publicKeyFilePaths'
            Stream[] publicKeys = publicKeyStreams.ToArray();

            if (privateKeyStream == null)
                throw new ArgumentException("PrivateKeyStream");
            if (passPhrase == null)
                throw new ArgumentNullException("Invalid Pass Phrase.");
            foreach (Stream publicKey in publicKeys)
            {
                if (publicKey == null)
                    throw new ArgumentException("PublicKeyStream");
            }

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return publicKeyStreams.Select(x => Utilities.ReadPublicKey(x)).ToList();
            });
            _secretKey = new Lazy<PgpSecretKey>(() =>
            {
                return ReadSecretKey(privateKeyStream);
            });
            _secretKeys = new Lazy<PgpSecretKeyRingBundle>(() =>
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
                {
                    return new PgpSecretKeyRingBundle(inputStream);
                }
            });
            _privateKey = new Lazy<PgpPrivateKey>(() =>
            {
                return ReadPrivateKey(passPhrase);
            });
            _passPhrase = passPhrase;
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
            if (String.IsNullOrEmpty(publicKey))
                throw new ArgumentException("PublicKey");

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKey.GetStream()) };
            });
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
                throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFile.FullName));

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyFile) };
            });
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
            foreach (string publicKey in publicKeys)
            {
                if (String.IsNullOrEmpty(publicKey))
                    throw new ArgumentException(nameof(publicKey));
            }

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return publicKeys.Select(x => Utilities.ReadPublicKey(x.GetStream())).ToList();
            });
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
                    throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", publicKeyFile.FullName));
            }

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return publicKeyFiles.Select(x => Utilities.ReadPublicKey(x)).ToList();
            });
        }

        public EncryptionKeys(Stream publicKeyStream)
        {
            if (publicKeyStream == null)
                throw new ArgumentException("PublicKeyStream");

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return new List<PgpPublicKey>() { Utilities.ReadPublicKey(publicKeyStream) };
            });
        }

        public EncryptionKeys(IEnumerable<Stream> publicKeyStreams)
        {
            Stream[] publicKeys = publicKeyStreams.ToArray();

            foreach (Stream publicKey in publicKeys)
            {
                if (publicKey == null)
                    throw new ArgumentException("PublicKeyStream");
            }

            _publicKeys = new Lazy<IEnumerable<PgpPublicKey>>(() =>
            {
                return publicKeyStreams.Select(x => Utilities.ReadPublicKey(x)).ToList();
            });
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

        #endregion Public Methods

        #region Secret Key

        private PgpSecretKey ReadSecretKey(string privateKeyPath)
        {
            PgpSecretKey foundKey = GetFirstSecretKey(SecretKeys);
            if (foundKey != null)
                return foundKey;
            throw new ArgumentException("Can't find signing key in key ring.");
        }

        private PgpSecretKey ReadSecretKey(FileInfo privateKeyFile)
        {
            PgpSecretKey foundKey = GetFirstSecretKey(SecretKeys);
            if (foundKey != null)
                return foundKey;
            throw new ArgumentException("Can't find signing key in key ring.");
        }

        private PgpSecretKey ReadSecretKey(Stream privateKeyStream)
        {
            PgpSecretKey foundKey = GetFirstSecretKey(SecretKeys);
            if (foundKey != null)
                return foundKey;
            throw new ArgumentException("Can't find signing key in key ring.");
        }

        /// <summary>
        /// Return the first key we can use to encrypt.
        /// Note: A file can contain multiple keys (stored in "key rings")
        /// </summary>
        private PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                PgpSecretKey key = kRing.GetSecretKeys()
                    .Cast<PgpSecretKey>()
                    .Where(k => k.IsSigningKey)
                    .FirstOrDefault();
                if (key != null)
                    return key;
            }
            return null;
        }

        #endregion Secret Key

        #region Public Key
       
        private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key = kRing.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .Where(k => k.IsEncryptionKey)
                    .FirstOrDefault();
                if (key != null)
                    return key;
            }
            return null;
        }

        #endregion Public Key

        #region Private Key

        private PgpPrivateKey ReadPrivateKey(string passPhrase)
        {
            PgpPrivateKey privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());
            if (privateKey != null)
                return privateKey;

            throw new ArgumentException("No private key found in secret key.");
        }

        #endregion Private Key
    }
}
