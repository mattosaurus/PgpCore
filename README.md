# PgpCore

![.NET](https://github.com/mattosaurus/PgpCore/actions/workflows/build-on-pr.yml/badge.svg)

A .NET Core class library for using PGP.

This is based on <a href="https://github.com/Cinchoo/ChoPGP" alt="ChoPGP">ChoPGP</a> but updated to .NET Standard and to add in a missing utilities class.

# Installation
To use PgpCore in your C# project download it from [NuGet](https://www.nuget.org/packages/PgpCore).

Once you have the PgpCore libraries properly referenced in your project, you can include calls to them in your code.

Add the following namespaces to use the library:

```C#
using PgpCore;
```
# Dependencies
* Portable.BouncyCastle (>= 1.9.0)

# Usage
This is intended for usage in projects [targeting .NET Standard 2.0](https://dotnet.microsoft.com/platform/dotnet-standard#versions).

# Azure Function Example
If you want a (basic) example of how you can use an Azure Function to encrypt/decrypt from Azure Blob Storage I've created a sample project [here](https://github.com/mattosaurus/PgpEncrypt).

# Performance
By default encrypted files are armoured. [It is suggested](https://github.com/mattosaurus/PgpCore/pull/312#issuecomment-2931559301) that for larger files this is disabled as it can significantly increase the file size and processing time. To disable armouring set the `armour` property to `false`.

## Methods

* [Generate Key](#generate-key)
* [Inspect](#inspect)
* [Encrypt](#encrypt)
* [Sign](#sign)
* [Clear Sign](#clear-sign)
* [Encrypt and Sign](#encrypt-and-sign)
* [Decrypt](#decrypt)
* [Verify](#verify)
* [Verify Clear](#verify-clear)
* [Decrypt and Verify](#decrypt-and-verify)

## Settings
* [Compression Algorithm](#compressionalgorithm)
* [Symmetric Key Algorithm](#symmetrickeyalgorithm)
* [Pgp Signature Type](#pgpsignaturetype)
* [Public Key Algorithm](#publickeyalgorithm)
* [File Type](#filetype)
* [Hash Algorithm Tag](#hashalgorithmtag)

#### Generate Key
Generate a new public and private key for the provided username and password.

[`gpg --gen-key`](https://www.gnupg.org/gph/en/manual/c14.html)
### GenerateKey
```C#
using (PGP pgp = new PGP())
{
	// Generate keys
	pgp.GenerateKey(new FileInfo(@"C:\TEMP\Keys\public.asc"), new FileInfo(@"C:\TEMP\Keys\private.asc"), "email@email.com", "password");
}
```
#### Inspect
Inspect the provided file, stream or string and return a [PGPInspectResult](https://github.com/mattosaurus/PgpCore/blob/master/PgpCore/Models/PGPInspectResult.cs) object that contains details on the messages encryption and sign status as well as additional information on filename, headers, etc. where available. 

[`gpg --list-packets "C:\TEMP\Content\encrypted.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
### Inspect File
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

// Reference input file
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\encrypted.pgp");

// Inspect
PGP pgp = new PGP();
PgpInspectResult result = await pgp.InspectAsync(inputFile);
```
### Inspect Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, "password");

PGP pgp = new PGP(encryptionKeys);

// Reference input stream
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encrypted.pgp", FileMode.Open))
	// Inspect
	PgpInspectResult result = await pgp.InspectAsync(inputFileStream);
```
### Inspect String
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
string privatyeKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

// Inspect
PGP pgp = new PGP(encryptionKeys);
PgpInspectResult result = await pgp.InspectAsync("String to inspect");
```
### Encrypt
Encrypt the provided file, stream or string using a public key.

Optional headers can be provided to include in the encrypted file. These can be set by providing a `Dictionary<string, string>` to the `headers` parameter. The key of the dictionary will be the header name and the value will be the header value.

[`gpg --output "C:\TEMP\Content\encrypted.pgp" --encrypt "C:\TEMP\Content\content.txt"`](https://www.gnupg.org/gph/en/manual/x110.html)
#### Encrypt File
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo encryptedFile = new FileInfo(@"C:\TEMP\Content\encrypted.pgp");

// Encrypt
PGP pgp = new PGP(encryptionKeys);
await pgp.EncryptAsync(inputFile, encryptedFile);
```
#### Encrypt Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream);

PGP pgp = new PGP(encryptionKeys);

// Reference input/output files
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\encrypted.pgp"))
	// Encrypt
	await pgp.EncryptAsync(inputFileStream, outputFileStream);
```
#### Encrypt String
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Encrypt
PGP pgp = new PGP(encryptionKeys);
string encryptedContent = await pgp.EncryptAsync("String to encrypt");
```
### Sign
Sign the provided file or stream using a private key.

Optional headers can be provided to include in the signed file. These can be set by providing a `Dictionary<string, string>` to the `headers` parameter. The key of the dictionary will be the header name and the value will be the header value.

[`gpg --output "C:\TEMP\Content\content.txt" --sign "C:\TEMP\Content\signed.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### Sign File
```C#
// Load keys
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo signedFile = new FileInfo(@"C:\TEMP\Content\signed.pgp");

// Sign
PGP pgp = new PGP(encryptionKeys);
await pgp.SignAsync(inputFile, signedFile);
```
#### Sign Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(privateKeyStream, "password");

PGP pgp = new PGP(encryptionKeys);

// Reference input/output files
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\signed.pgp"))
	// Sign
	await pgp.SignAsync(inputFileStream, outputFileStream);
```
#### Sign String
```C#
// Load keys
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Sign
string signedContent = await pgp.SignAsync("String to sign");
```
### Clear Sign
Clear sign the provided file, stream, or string using a private key so that it is still human readable. A common use of digital signatures is to sign usenet postings or email messages. In such situations it is undesirable to compress the document while signing it. This is because the signature would then depend on the compression algorithm used. This is problematic when different people use different compression algorithms. To overcome this problem, the OpenPGP digital signature format has a special type of signature that is not computed on the message itself. Instead, the signature is computed on a "cleartext" version of the message - a version that is exactly the same as the original message except that it is not compressed and certain types of information (such as the end of line markers) are not included. This cleartext version is then compressed and the signature is appended to the compressed cleartext to produce the final message.

[`gpg --output "C:\TEMP\Content\content.txt" --clearsign  "C:\TEMP\Content\clearSigned.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### Clear Sign File
```C#
// Load keys
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo signedFile = new FileInfo(@"C:\TEMP\Content\signed.pgp");

// Sign
PGP pgp = new PGP(encryptionKeys);
await pgp.ClearSignAsync(inputFile, signedFile);
```
#### Clear Sign Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(privateKeyStream, "password");

PGP pgp = new PGP(encryptionKeys);

// Reference input/output files
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\signed.pgp"))
	// Sign
	await pgp.ClearSignAsync(inputFileStream, outputFileStream);
```
#### Clear Sign String
```C#
// Load keys
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Sign
string signedContent = await pgp.ClearSignAsync("String to sign");
```
### Encrypt and Sign
Encrypt the provided file, stream or string using a public key and sign using your private key. You usually encrypt with the public key of your counterparty so they can decrypt with their private key and sign with your private key so they can verify with your public key.

Although this method is called `EncryptAndSign` the signature will actually be included within the encrypted message rather than being appended to the encrypted message. This ensures that the original message was composed by the holder of the private key.

[`gpg --encrypt --sign --recipient 'some user ID value' "C:\TEMP\keys\content.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
#### Encrypt File And Sign
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo encryptedSignedFile = new FileInfo(@"C:\TEMP\Content\encryptedSigned.pgp");

// Encrypt and Sign
PGP pgp = new PGP(encryptionKeys);
await pgp.EncryptAndSignAsync(inputFile, encryptedSignedFile);
```
#### Encrypt Stream And Sign
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, "password");

PGP pgp = new PGP(encryptionKeys);

// Reference input/output files
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\signed.pgp"))
	// Encrypt and Sign
	await pgp.EncryptAndSignAsync(inputFileStream, outputFileStream);
```
#### Encrypt String And Sign
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Encrypt and Sign
string encryptedSignedContent = await pgp.EncryptAndSignAsync("String to encrypt and sign");
```
### Decrypt
Decrypt the provided file, stream or string using the matching private key and passphrase.

[`gpg --output "C:\TEMP\Content\decrypted.txt" --decrypt "C:\TEMP\Content\encrypted.pgp"`](https://www.gnupg.org/gph/en/manual/x110.html)
#### Decrypt File
```C#
// Load keys
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\encryptedContent.pgp");
FileInfo decryptedFile = new FileInfo(@"C:\TEMP\Content\decrypted.txt");

// Decrypt
PGP pgp = new PGP(encryptionKeys);
await pgp.DecryptAsync(inputFile, decryptedFile);
```
#### Decrypt Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(privateKeyStream, "password");

PGP pgp = new PGP(encryptionKeys);

// Reference input/output files
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedContent.pgp", FileMode.Open))
using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\decrypted.txt"))
	// Decrypt
	await pgp.DecryptAsync(inputFileStream, outputFileStream);
```
#### Decrypt String
```C#
// Load keys
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Decrypt
string decryptedContent = await pgp.DecryptAsync("String to decrypt");
```
### Verify
Verify that the file, stream or string was signed by the matching private key of the counterparty.

[`gpg --verify "C:\TEMP\Content\signed.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### Verify File
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");

// Verify
PGP pgp = new PGP(encryptionKeys);
bool verified = await pgp.VerifyAsync(inputFile);
```
#### Verify Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream);

PGP pgp = new PGP(encryptionKeys);

// Reference input file
bool verified;
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedContent.pgp", FileMode.Open))
	// Verify
	verified = await pgp.VerifyAsync(inputFileStream);
```
#### Verify String
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify
bool verified = await pgp.VerifyAsync("String to verify");
```
### Verify and Read
Verify that the file, stream was signed by the matching private key of the counterparty. This is an overload of the `Verify` method that takes an additional output argument. Please note that this is not available for the string based method.

#### Verify And Read File
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");
FileInfo outputFile = new FileInfo(@"C:\TEMP\Content\decryptedContent.txt");

// Verify and read
PGP pgp = new PGP(encryptionKeys);
bool verified = await pgp.VerifyAsync(inputFile, outputFile);
```

#### Verify And Read Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream);

PGP pgp = new PGP(encryptionKeys);

// Reference input file
bool verified;
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedContent.pgp", FileMode.Open))
using (FileStream outputFileStream = new FileStream(@"C:\TEMP\Content\decryptedContent.pgp", FileMode.Open))
	// Verify and read
	verified = await pgp.VerifyAsync(inputFileStream);
```

#### Verify And Read String
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify and read
string output = string.Empty;
bool verified = await pgp.VerifyAsync("String to verify", output);
```
### Verify Clear
Verify that the clear signed file or stream was signed by the matching private key of the counterparty.

[`gpg --verify "C:\TEMP\Content\clearSigned.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### Verify Clear File
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");

// Verify
PGP pgp = new PGP(encryptionKeys);
bool verified = await pgp.VerifyClearAsync(inputFile);
```
#### Verify Clear Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream);

PGP pgp = new PGP(encryptionKeys);

// Reference input file
bool verified;
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedContent.pgp", FileMode.Open))
	// Verify
	verified = await pgp.VerifyClearAsync(inputFileStream);
```
#### Verify Clear String
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify
bool verified = await pgp.VerifyClearAsync("String to verify");
```
### Verify and Read Clear
Verify that the clear signed file or stream was signed by the matching private key of the counterparty. This is an overload of the `VerifyClear` method that takes an additional output argument.

#### Verify And Read Clear File
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");
FileInfo outputFile = new FileInfo(@"C:\TEMP\Content\decryptedContent.txt");

// Verify and read
PGP pgp = new PGP(encryptionKeys);
bool verified = await pgp.VerifyClearAsync(inputFile, outputFile);
```
#### Verify And Read Clear Stream
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
    encryptionKeys = new EncryptionKeys(publicKeyStream);

PGP pgp = new PGP(encryptionKeys);

// Reference input file
bool verified;
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedContent.pgp", FileMode.Open))
using (FileStream outputFileStream = new FileStream(@"C:\TEMP\Content\decryptedContent.pgp", FileMode.Open))
    // Verify and read
    verified = await pgp.VerifyClearAsync(inputFileStream);
```
#### Verify And Read Clear String
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify and read
string output = string.Empty;
bool verified = await pgp.VerifyClearAsync("String to verify", output);
```
### Decrypt and Verify
Decrypt and then verify the provided encrypted and signed file, stream or string. Usually your counterparty will encrypt with your public key and sign with their private key so you can decrypt with your private key and verify with their public key.

The `DecryptAndVerify` methods will only work with files that have been encrypted and signed using the `EncryptAndSign` methods. This is because the signature is included within the encrypted message rather than being appended to the encrypted message. If a file is first encrypted using an `Encrypt` method and then signed using a `Sign` method then the signature will be appended to the encrypted message rather than embedded within it and the `DecryptAndVerify` methods will not be able to verify the signature.

[`gpg --output "C:\TEMP\Content\encryptedAndSigned.pgp" --decrypt "C:\TEMP\Content\decryptedAndVerified.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
#### Decrypt File And Verify
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\encryptedSigned.pgp");
FileInfo outputFile = new FileInfo(@"C:\TEMP\Content\content.txt");

// Decrypt and Verify
PGP pgp = new PGP(encryptionKeys);
await pgp.DecryptAndVerifyAsync(inputFile, outputFile);
```
#### Decrypt Stream And Verify
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
    encryptionKeys = new EncryptionKeys(publicKeyStream, privateKeyStream, "password");

PGP pgp = new PGP(encryptionKeys);

// Reference input/output files
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedSigned.pgp", FileMode.Open))
using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\content.txtp"))
    // Decrypt and Verify
    await pgp.DecryptAndVerifyAsync(inputFileStream, outputFileStream);
```
#### Decrypt String And Verify
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Decrypt and Verify
string encryptedSignedContent = await pgp.DecryptAndVerifyAsync("String to decrypt and verify");
```
## Settings
The PGP object contains a variety of settings properties that can be used to determine how files are encrypted.
### CompressionAlgorithm
The compression algorithim to be used on the message. This is applied prior to encryption, either to the message or the signed message.
- Uncompressed - **Default**
- Zip
- ZLib
- BZip2
### SymmetricKeyAlgorithm
The private key encryption algorithm.
> Although TripleDes is the default, it is outdated and being [discouraged by security institutions like NIST](https://en.wikipedia.org/wiki/Triple_DES). Aes is recommended.

- Null
- Idea
- TripleDes - **Default**
- Cast5
- Blowfish
- Safer
- Des
- Aes128
- Aes192
- Aes256
- Twofish
- Camellia128
- Camellia192
- Camellia256
### PgpSignatureType
The type of signature to be used for file signing.
- BinaryDocument
- CanonicalTextDocument
- StandAlone
- DefaultCertification - **Default**
- NoCertification
- CasualCertification
- PositiveCertification
- SubkeyBinding
- PrimaryKeyBinding
- DirectKey
- KeyRevocation
- SubkeyRevocation
- CertificationRevocation
- Timestamp
### PublicKeyAlgorithm
The public key encryption algorithim.
- RsaGeneral - **Default**
- RsaEncrypt
- RsaSign
- ElGamalEncrypt
- Dsa
- ECDH
- ECDsa
- ElGamalGeneral
- DiffieHellman
- EdDsa
### FileType
Encoding to be used for the output file.
- Binary - **Default**
- Text
- UTF8
### HashAlgorithmTag
The hash algorithim to be used by the signature.
- MD5
- Sha1 - **Default**
- RipeMD160
- DoubleSha
- MD2
- Tiger192
- Haval5pass160
- Sha256
- Sha384
- Sha512
- Sha224
