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
Async versions of the below methods are available apart from for GenerateKey.

### GenerateKey
Generate a new public and private key for the provided username and password, same with methods that accept a stream rather than a file path.

```C#
using (PGP pgp = new PGP())
{
	// Generate keys
	pgp.GenerateKey(@"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "email@email.com", "password");
}
```

[`gpg --gen-key`](https://www.gnupg.org/gph/en/manual/c14.html)

### EncryptFile
Encrypt the provided file using a public key.

[`gpg --output "C:\TEMP\keys\content__encrypted.pgp" --encrypt "C:\TEMP\keys\content.txt"`](https://www.gnupg.org/gph/en/manual/x110.html)
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

### DecryptFile
Decrypt the provided file using the matching private key and passphrase.

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

A good resource for generating keys and messages is <a href="https://wp2pgpmail.com/pgp-key-generator/" alt="PGP Key Generator">PGP Key Generator</a>.
