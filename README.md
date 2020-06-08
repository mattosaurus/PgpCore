# PgpCore
A .NET Core class library for using PGP.

This is based on <a href="https://github.com/Cinchoo/ChoPGP" alt="ChoPGP">ChoPGP</a> but updated to .NET Core framework and to add in a missing utilities class.

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
BouncyCastle.NetCore (>= 1.8.1.3)

Microsoft.NETCore.App (>= 1.1.2)

# Usage
This is intended for usage in .NET Core projects, the latest version that works with .NET Framework is v2.2.0.

## Methods

* [Generate Key](#generate-key)
  * [GenerateKey](#generatekey)
* [Encrypt](#encrypt)
  * [EncryptFile](#encryptfile)
  * [EncryptFileAsync](#encryptfileasync)
  * [EncryptStream](#encryptstream)
  * [EncryptStreamAsync](#encryptstreamasync)
* [Sign](#sign)
  * [SignFile](#signfile)
  * [SignFileAsync](#signfileasync)
  * [SignStream](#signstream)
  * [SignStreamAsync](#signstreamasync)
* [ClearSign](#clearsign)
  * [ClearSignFile](#clearsignfile)
  * [ClearSignFileAsync](#clearsignfileasync)
  * [ClearSignStream](#clearsignstream)
  * [ClearSignStreamAsync](#clearsignstreamasync)
* [Encrypt and Sign](#encrypt-and-sign)
  * [EncryptFileAndSign](#encryptfileandsign)
  * [EncryptFileAndSignAsync](#encryptfileandsignasync)
  * [EncryptStreamAndSign](#encryptstreamandsign)
  * [EncryptStreamAndSignAsync](#encryptstreamandsignasync)
* [Decrypt](#decrypt)
  * [DecryptFile](#decryptfile)
  * [DecryptFileAsync](#decryptfileasync)
  * [DecryptStream](#decryptstream)
  * [DecryptStreamAsync](#decryptstreamasync)
* [Verify](#verify)
  * [VerifyFile](#verifyfile)
  * [VerifyFileAsync](#verifyfileasync)
  * [VerifyStream](#verifystream)
  * [VerifyStreamAsync](#verifystreamasync)
* [VerifyClear](#verify)
  * [VerifyClearFile](#verifyclearfile)
  * [VerifyClearFileAsync](#verifyclearfileasync)
  * [VerifyClearStream](#verifyclearstream)
  * [VerifyClearStreamAsync](#verifyclearstreamasync)
* [Decrypt and Verify](#decrypt-and-verify)
  * [DecryptFileAndVerify](#decryptfileandverify)
  * [DecryptFileAndVerifyAsync](#decryptfileandverifyasync)
  * [DecryptStreamAndVerify](#decryptstreamandverify)
  * [DecryptStreamAndVerifyAsync](#decryptstreamandverifyasync)

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
Encrypt the provided file or stream using a public key.

[`gpg --output "C:\TEMP\Content\encrypted.pgp" --encrypt "C:\TEMP\Content\content.txt"`](https://www.gnupg.org/gph/en/manual/x110.html)
#### EncryptFile
```C#
using (PGP pgp = new PGP())
{
	// Encrypt file
	pgp.EncryptFile(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\encrypted.pgp", @"C:\TEMP\Keys\public.asc", true, true);
}
```
#### EncryptFileAsync
```C#
using (PGP pgp = new PGP())
{
	// Encrypt file
	await pgp.EncryptFileAsync(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\encrypted.pgp", @"C:\TEMP\Keys\public.asc", true, true);
}
```
#### EncryptStream
```C#
using (PGP pgp = new PGP())
{
	// Encrypt stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\encrypted.pgp"))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
		pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream, true, true);
}
```
#### EncryptStreamAsync
```C#
using (PGP pgp = new PGP())
{
	// Encrypt stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\encrypted.pgp"))
	using (Stream publicKeyStream = new FileStream(@"C:\TEMP\Keys\public.asc", FileMode.Open))
		await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, publicKeyStream, true, true);
}
```
### Sign
Sign the provided file or stream using a private key.

[`gpg --output "C:\TEMP\Content\content.txt" --sign "C:\TEMP\Content\signed.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### SignFile
```C#
using (PGP pgp = new PGP())
{
	// Sign file
	pgp.SignFile(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\signed.pgp", @"C:\TEMP\Keys\private.asc", "password", true, true);
}
```
#### SignFileAsync
```C#
using (PGP pgp = new PGP())
{
	// Sign file
	await pgp.SignFileAsync(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\signed.pgp", @"C:\TEMP\Keys\private.asc", "password", true, true);
}
```
#### SignStream
```C#
using (PGP pgp = new PGP())
{
	// Sign stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\signed.pgp"))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		pgp.SignFile(inputFileStream, outputFileStream, privateKeyStream, "password", true, true);
}
```
#### SignStreamAsync
```C#
using (PGP pgp = new PGP())
{
	// Sign stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\signed.pgp"))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		await pgp.SignFileAsync(inputFileStream, outputFileStream, privateKeyStream, "password", true, true);
}
```
### Clear Sign
Clear sign the provided file or stream using a private key so that it is still human readable.

[`gpg --output "C:\TEMP\Content\content.txt" --clearsign  "C:\TEMP\Content\clearSigned.pgp"`](https://www.gnupg.org/gph/en/manual/x135.html)
#### ClearSignFile
```C#
using (PGP pgp = new PGP())
{
	// Clear sign file
	pgp.ClearSignFile(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\clearSigned.pgp", @"C:\TEMP\Keys\private.asc", "password", true, true);
}
```
#### ClearSignFileAsync
```C#
using (PGP pgp = new PGP())
{
	// Clear sign file
	await pgp.ClearSignFileAsync(@"C:\TEMP\Content\content.txt", @"C:\TEMP\Content\clearSigned.pgp", @"C:\TEMP\Keys\private.asc", "password", true, true);
}
```
#### ClearSignStream
```C#
using (PGP pgp = new PGP())
{
	// Clear sign stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\clearSigned.pgp"))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		pgp.ClearSignFile(inputFileStream, outputFileStream, privateKeyStream, "password", true, true);
}
```
#### ClearSignStreamAsync
```C#
using (PGP pgp = new PGP())
{
	// Clear sign stream
	using (FileStream inputFileStream = new FileStream(@"C:\TEMP\Content\content.txt", FileMode.Open))
	using (Stream outputFileStream = File.Create(@"C:\TEMP\Content\clearSigned.pgp"))
	using (Stream privateKeyStream = new FileStream(@"C:\TEMP\Keys\private.asc", FileMode.Open))
		await pgp.ClearSignFileAsync(inputFileStream, outputFileStream, privateKeyStream, "password", true, true);
}
```
### Encrypt and Sign
Encrypt the provided file or stream using a public key and sign using your private key. You usually encrypt with the public key of your counterparty so they can decrypt with their private key and sign with your private key so they can verify with your public key.

[`pg --encrypt --sign --recipient 'some user ID value' "C:\TEMP\keys\content.txt"`](https://medium.com/@acparas/how-to-encrypt-and-sign-a-file-with-gpg-531070b2fa6d)
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
