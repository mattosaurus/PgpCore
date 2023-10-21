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

## Methods

* [Generate Key](#generate-key)
  * [GenerateKey](#generatekey)
* [Encrypt](#encrypt)
  * [EncryptFileAsync](#encryptfileasync)
  * [EncryptStreamAsync](#encryptstreamasync)
  * [EncryptArmoredStringAsync](#encryptarmoredstringasync)
* [Sign](#sign)
  * [SignFileAsync](#signfileasync)
  * [SignStreamAsync](#signstreamasync)
  * [SignArmoredStringAsync](#signarmoredstringasync)
* [ClearSign](#clearsign)
  * [ClearSignFileAsync](#clearsignfileasync)
  * [ClearSignStreamAsync](#clearsignstreamasync)
  * [ClearSignArmoredStringAsync](#clearsignarmoredstringasync)
* [Encrypt and Sign](#encrypt-and-sign)
  * [EncryptFileAndSignAsync](#encryptfileandsignasync)
  * [EncryptStreamAndSignAsync](#encryptstreamandsignasync)
  * [EncryptArmoredStringAndSignAsync](#encryptarmoredstringandsignasync)
* [Decrypt](#decrypt)
  * [DecryptFileAsync](#decryptfileasync)
  * [DecryptStreamAsync](#decryptstreamasync)
  * [DecryptArmoredStringAsync](#decryptarmoredstringasync)
* [Verify](#verify)
  * [VerifyFileAsync](#verifyfileasync)
  * [VerifyStreamAsync](#verifystreamasync)
  * [VerifyArmoredStringAsync](#verifyarmoredstringasync)
* [VerifyClear](#verify)
  * [VerifyClearFileAsync](#verifyclearfileasync)
  * [VerifyClearStreamAsync](#verifyclearstreamasync)
  * [VerifyClearArmoredStringAsync](#verifycleararmoredstringasync)
* [Verify and Read Clear](#verifyandreadclear)
  * [VerifyAndReadClearFileAsync](#verifyandreadclearfilessync)
  * [VerifyAndReadClearStreamAsync](#verifyandreadclearstreamasync)
  * [VerifyAndReadClearArmoredStringAsync](#verifyandreadcleararmoredstringasync)
* [Decrypt and Verify](#decrypt-and-verify)
  * [DecryptFileAndVerifyAsync](#decryptfileandverifyasync)
  * [DecryptStreamAndVerifyAsync](#decryptstreamandverifyasync)
  * [DecryptArmoredStringAndVerifyAsync](#decryptarmoredstringandverifyasync)

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
	pgp.GenerateKey(@"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "email@email.com", "password");
}
```
### Encrypt
Encrypt the provided file, stream or string using a public key.

[`gpg --output "C:\TEMP\Content\encrypted.pgp" --encrypt "C:\TEMP\Content\content.txt"`](https://www.gnupg.org/gph/en/manual/x110.html)
#### EncryptFileAsync
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo encryptedFile = new FileInfo(@"C:\TEMP\Content\encrypted.pgp");

// Encrypt
PGP pgp = new PGP(encryptionKeys);
await pgp.EncryptFileAsync(inputFile, encryptedFile);
```
#### EncryptStreamAsync
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
	await pgp.EncryptStreamAsync(inputFileStream, outputFileStream);
```
#### EncryptArmoredStringAsync
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Encrypt
PGP pgp = new PGP(encryptionKeys);
string encryptedContent = await pgp.EncryptArmoredStringAsync("String to encrypt");
```
### Sign
Sign the provided file or stream using a private key.

[`gpg --output "C:\TEMP\Content\content.txt" --sign "C:\TEMP\Content\signed.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### SignFileAsync
```C#
// Load keys
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo signedFile = new FileInfo(@"C:\TEMP\Content\signed.pgp");

// Sign
PGP pgp = new PGP(encryptionKeys);
await pgp.SignFileAsync(inputFile, signedFile);
```
#### SignStreamAsync
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
	await pgp.SignStreamAsync(inputFileStream, outputFileStream);
```
#### SignArmoredStringAsync
```C#
// Load keys
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Sign
string signedContent = await pgp.SignArmoredStringAsync("String to sign");
```
### Clear Sign
Clear sign the provided file, stream, or string using a private key so that it is still human readable. A common use of digital signatures is to sign usenet postings or email messages. In such situations it is undesirable to compress the document while signing it. This is because the signature would then depend on the compression algorithm used. This is problematic when different people use different compression algorithms. To overcome this problem, the OpenPGP digital signature format has a special type of signature that is not computed on the message itself. Instead, the signature is computed on a "cleartext" version of the message - a version that is exactly the same as the original message except that it is not compressed and certain types of information (such as the end of line markers) are not included. This cleartext version is then compressed and the signature is appended to the compressed cleartext to produce the final message.

[`gpg --output "C:\TEMP\Content\content.txt" --clearsign  "C:\TEMP\Content\clearSigned.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### ClearSignFileAsync
```C#
// Load keys
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
FileInfo signedFile = new FileInfo(@"C:\TEMP\Content\signed.pgp");

// Sign
PGP pgp = new PGP(encryptionKeys);
await pgp.ClearSignFileAsync(inputFile, signedFile);
```
#### ClearSignStreamAsync
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
	await pgp.ClearSignStreamAsync(inputFileStream, outputFileStream);
```
#### ClearSignArmoredStringAsync
```C#
// Load keys
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Sign
string signedContent = await pgp.ClearSignArmoredStringAsync("String to sign");
```
### Encrypt and Sign
Encrypt the provided file, stream or string using a public key and sign using your private key. You usually encrypt with the public key of your counterparty so they can decrypt with their private key and sign with your private key so they can verify with your public key.

Although this method is called `EncryptAndSign` the signature will actually be included within the encrypted message rather than being appended to the encrypted message. This ensures that the original message was composed by the holder of the private key.

[`gpg --encrypt --sign --recipient 'some user ID value' "C:\TEMP\keys\content.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
#### EncryptFileAndSignAsync
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
await pgp.EncryptFileAndSignAsync(inputFile, encryptedSignedFile);
```
#### EncryptStreamAndSignAsync
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
	await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream);
```
#### EncryptArmoredStringAndSignAsync
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Encrypt and Sign
string encryptedSignedContent = await pgp.EncryptArmoredStringAndSignAsync("String to encrypt and sign");
```
### Decrypt
Decrypt the provided file, stream or string using the matching private key and passphrase.

[`gpg --output "C:\TEMP\Content\decrypted.txt" --decrypt "C:\TEMP\Content\encrypted.pgp"`](https://www.gnupg.org/gph/en/manual/x110.html)
#### DecryptFileAsync
```C#
// Load keys
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\encryptedContent.pgp");
FileInfo decryptedFile = new FileInfo(@"C:\TEMP\Content\decrypted.txt");

// Decrypt
PGP pgp = new PGP(encryptionKeys);
await pgp.DecryptFileAsync(inputFile, decryptedFile);
```
#### DecryptStreamAsync
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
	await pgp.DecryptStreamAsync(inputFileStream, outputFileStream);
```
#### DecryptArmoredStringAsync
```C#
// Load keys
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Decrypt
string decryptedContent = await pgp.DecryptArmoredStringAsync("String to decrypt");
```
### Verify
Verify that the file, stream or string was signed by the matching private key of the counterparty.

[`gpg --verify "C:\TEMP\Content\signed.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### VerifyFileAsync
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");

// Verify
PGP pgp = new PGP(encryptionKeys);
bool verified = await pgp.VerifyFileAsync(inputFile);
```
#### VerifyStreamAsync
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
	verified = await pgp.VerifyStreamAsync(inputFileStream);
```
#### VerifyArmoredStringAsync
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify
bool verified = await pgp.VerifyArmoredStringAsync("String to verify");
```
### Verify Clear
Verify that the clear signed file or stream was signed by the matching private key of the counterparty.

[`gpg --verify "C:\TEMP\Content\clearSigned.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### VerifyClearFileAsync
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");

// Verify
PGP pgp = new PGP(encryptionKeys);
bool verified = await pgp.VerifyClearFileAsync(inputFile);
```
#### VerifyClearStreamAsync
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
	verified = await pgp.VerifyClearStreamAsync(inputFileStream);
```
#### VerifyClearArmoredStringAsync
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify
bool verified = await pgp.VerifyClearArmoredStringAsync("String to verify");
```
### Verify and Read Clear
Verify that the clear signed file or stream was signed by the matching private key of the counterparty. This method returns a `VerificationResult` object that contains a boolean indicating if the message was verified or not along with the message content.

#### VerifyAndReadClearFileAsync
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

// Reference input
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signedContent.pgp");

// Verify and read
PGP pgp = new PGP(encryptionKeys);
VerificationResult verificationResult = await pgp.VerifyAndReadClearFileAsync(inputFile);
bool verified = verificationResult.IsVerified;
string content = verificationResult.Content;
```
#### VerifyAndReadClearStreamAsync
```C#
// Load keys
EncryptionKeys encryptionKeys;
using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	encryptionKeys = new EncryptionKeys(publicKeyStream);

PGP pgp = new PGP(encryptionKeys);

// Reference input file
bool verified;
using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedContent.pgp", FileMode.Open))
	// Verify and read
	VerificationResult verificationResult = await pgp.VerifyAndReadClearStreamAsync(inputFileStream);
	bool verified = verificationResult.IsVerified;
	string content = verificationResult.Content;
```
#### VerifyAndReadClearArmoredStringAsync
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

PGP pgp = new PGP(encryptionKeys);

// Verify and read
VerificationResult verificationResult = await pgp.VerifyAndReadClearArmoredStringAsync("String to verify");
bool verified = verificationResult.IsVerified;
string content = verificationResult.Content;
```
### Decrypt and Verify
Decrypt and then verify the provided encrypted and signed file, stream or string. Usually your counterparty will encrypt with your public key and sign with their private key so you can decrypt with your private key and verify with their public key.

[`gpg --output "C:\TEMP\Content\encryptedAndSigned.pgp" --decrypt "C:\TEMP\Content\decryptedAndVerified.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
#### DecryptFileAndVerifyAsync
```C#
// Load keys
FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

// Reference input/output files
FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\encryptedSigned.pgp");
FileInfo encryptedSignedFile = new FileInfo(@"C:\TEMP\Content\content.txt");

// Decrypt and Verify
PGP pgp = new PGP(encryptionKeys);
await pgp.DecryptFileAndVerifyAsync(inputFile, encryptedSignedFile);
```
#### DecryptStreamAndVerifyAsync
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
	await pgp.DecryptStreamAndVerifyAsync(inputFileStream, outputFileStream);
```
#### DecryptArmoredStringAndVerifyAsync
```C#
// Load keys
string publicKey = File.ReadAllText(@"C:\TEMP\Keys\public.asc");
string privateKey = File.ReadAllText(@"C:\TEMP\Keys\private.asc");
EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, "password");

PGP pgp = new PGP(encryptionKeys);

// Decrypt and Verify
string encryptedSignedContent = await pgp.DecryptArmoredStringAndVerifyAsync("String to decrypt and verify");
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
