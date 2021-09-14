# PgpCore

![.NET](https://github.com/mattosaurus/PgpCore/actions/workflows/dotnet.yml/badge.svg)

A .NET Core class library for using PGP.

This is based on <a href="https://github.com/Cinchoo/ChoPGP" alt="ChoPGP">ChoPGP</a> but updated to .NET Standard and to add in a missing utilities class.

# Installation
To use PgpCore in your C# project, you can either download the PgpCore C# .NET libraries directly from the Github repository or, if you have the NuGet package manager installed, you can grab them automatically.

```
PM> Install-Package PgpCore
```
Once you have the PgpCore libraries properly referenced in your project, you can include calls to them in your code.

Add the following namespaces to use the library:

```C#
using PgpCore;
```
# Dependencies
* Portable.BouncyCastle (>= 1.8.9)

# Usage
This is intended for usage in projects [targeting .NET Standard 2.0](https://dotnet.microsoft.com/platform/dotnet-standard#versions).

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
* [Decrypt and Verify](#decrypt-and-verify)
  * [DecryptFileAndVerifyAsync](#decryptfileandverifyasync)
  * [DecryptStreamAndVerifyAsync](#decryptstreamandverifyasync)
  * [DecryptArmoredStringAndVerifyAsync](#decryptarmoredstringandverifyasync)

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
Clear sign the provided file, stream, or string using a private key so that it is still human readable.

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
