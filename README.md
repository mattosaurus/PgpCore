# PgpCore

[![CircleCI](https://circleci.com/gh/mattosaurus/pgpcore/tree/master.svg?style=svg)](<https://circleci.com/gh/mattosaurus/pgpcore/tree/master>)

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
  * [SignArmoredStringAsync](#signarmoredstringsync)
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
await pgp.SignFileAsync(inputFile, encryptedFile);
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
PGP pgp = new PGP(encryptionKeys);
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
await pgp.ClearSignFileAsync(inputFile, encryptedFile);
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
PGP pgp = new PGP(encryptionKeys);
string signedContent = await pgp.ClearSignArmoredStringAsync("String to sign");
```
### Encrypt and Sign
Encrypt the provided file or stream using a public key and sign using your private key. You usually encrypt with the public key of your counterparty so they can decrypt with their private key and sign with your private key so they can verify with your public key.

[`gpg --encrypt --sign --recipient 'some user ID value' "C:\TEMP\keys\content.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
#### EncryptFileAndSign
```C#
using (PGP pgp = new PGP())
{
	// Encrypt file and sign
	pgp.EncryptFileAndSign(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\encryptedAndSigned.pgp", @"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "password", true, true);
}
```
#### EncryptFileAndSignAsync
```C#
using (PGP pgp = new PGP())
{
	// Encrypt file and sign
	await pgp.EncryptFileAndSignAsync(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\encryptedAndSigned.pgp", @"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "password", true, true);
}
```
#### EncryptStreamAndSign
```C#
using (PGP pgp = new PGP())
{
	// Encrypt and sign stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\encryptedAndSigned.pgp"))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		pgp.EncryptStreamAndSign(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, "password", true, true);
}
```
#### EncryptStreamAndSignAsync
```C#
using (PGP pgp = new PGP())
{
	// Encrypt and sign stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\encryptedAndSigned.pgp"))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, "password", true, true);
}
```
### Decrypt
Decrypt the provided file or stream using the matching private key and passphrase.

[`gpg --output "C:\TEMP\Content\decrypted.txt" --decrypt "C:\TEMP\Content\encrypted.pgp"`](https://www.gnupg.org/gph/en/manual/x110.html)
#### DecryptFile
```C#
using (PGP pgp = new PGP())
{
	// Decrypt file
	pgp.DecryptFile(@"C:\TEMP\Content\encrypted.pgp", @"C:\TEMP\Content\decrypted.txt", @"C:\TEMP\Keys\private.asc", "password");
}
```
#### DecryptFileAsync
```C#
using (PGP pgp = new PGP())
{
	// Decrypt file
	await pgp.DecryptFileAsync(@"C:\TEMP\Content\encrypted.pgp", @"C:\TEMP\Content\decrypted.txt", @"C:\TEMP\Keys\private.asc", "password");
}
```
#### DecryptStream
```C#
using (PGP pgp = new PGP())
{
	// Decrypt stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encrypted.pgp", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\decrypted.txt"))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, "password");
}
```
#### DecryptStreamAsync
```C#
using (PGP pgp = new PGP())
{
	// Decrypt stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encrypted.pgp", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\decrypted.txt"))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		await pgp.DecryptStreamAsync(inputFileStream, outputFileStream, privateKeyStream, "password");
}
```
### Verify
Verify that the file or stream was signed by the matching private key of the counterparty.

[`gpg --verify "C:\TEMP\Content\signed.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### VerifyFile
```C#
using (PGP pgp = new PGP())
{
	// Verify file
	bool verified = pgp.VerifyFile(@"C:\TEMP\Content\signed.pgp", @"C:\TEMP\Keys\public.asc");
}
```
#### VerifyFileAsync
```C#
using (PGP pgp = new PGP())
{
	// Verify file
	bool verified = await pgp.VerifyFileAsync(@"C:\TEMP\Content\signed.pgp", @"C:\TEMP\Keys\public.asc");
}
```
#### VerifyStream
```C#
using (PGP pgp = new PGP())
{
	// Verify stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		bool verified = pgp.VerifyFile(inputFileStream, publicKeyStream);
}
```
#### VerifyStreamAsync
```C#
using (PGP pgp = new PGP())
{
	// Verify stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		bool verified = await pgp.VerifyFileAsync(inputFileStream, publicKeyStream);
}
```
### Verify Clear
Verify that the clear signed file or stream was signed by the matching private key of the counterparty.

[`gpg --verify "C:\TEMP\Content\clearSigned.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### VerifyClearFile
```C#
using (PGP pgp = new PGP())
{
	// Verify clear file
	bool verified = pgp.VerifyClearFile(@"C:\TEMP\Content\signed.pgp", @"C:\TEMP\Keys\public.asc");
}
```
#### VerifyClearFileAsync
```C#
using (PGP pgp = new PGP())
{
	// Verify clear file
	bool verified = await pgp.VerifyClearFileAsync(@"C:\TEMP\Content\signed.pgp", @"C:\TEMP\Keys\public.asc");
}
```
#### VerifyClearStream
```C#
using (PGP pgp = new PGP())
{
	// Verify clear stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		bool verified = pgp.VerifyClearFile(inputFileStream, publicKeyStream);
}
```
#### VerifyClearStreamAsync
```C#
using (PGP pgp = new PGP())
{
	// Verify clear stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		bool verified = await pgp.VerifyClearFileAsync(inputFileStream, publicKeyStream);
}
```
### Decrypt and Verify
Decrypt and then verify the provided encrypted and signed file. Usually your counterparty will encrypt with your public key and sign with their private key so you can decrypt with your private key and verify with their public key.

[`gpg --output "C:\TEMP\Content\encryptedAndSigned.pgp" --decrypt "C:\TEMP\Content\decryptedAndVerified.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
#### DecryptFileAndVerify
```C#
using (PGP pgp = new PGP())
{
	// Decrypt file and verify
	pgp.DecryptFileAndVerify(@"C:\TEMP\Content\encryptedAndSigned.pgp", @"C:\TEMP\Content\decryptedAndVerified.txt",  @"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "password");
}
```
#### DecryptFileAndVerifyAsync
```C#
using (PGP pgp = new PGP())
{
	// Decrypt file and verify
	await pgp.DecryptFileAndVerifyAsync(@"C:\TEMP\Content\encryptedAndSigned.pgp", @"C:\TEMP\Content\decryptedAndVerified.txt",  @"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "password");
}
```
#### DecryptStreamAndVerify
```C#
using (PGP pgp = new PGP())
{
	// Decrypt stream and verify
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedAndSigned.pgp", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\decryptedAndVerified.txt"))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		pgp.DecryptStreamAndVerify(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, "password");
}
```
#### DecryptStreamAndVerifyAsync
```C#
using (PGP pgp = new PGP())
{
	// Decrypt stream and verify
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\encryptedAndSigned.pgp", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\decryptedAndVerified.txt"))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		await pgp.DecryptStreamAndVerifyAsync(inputFileStream, outputFileStream, publicKeyStream, privateKeyStream, "password");
}
```
