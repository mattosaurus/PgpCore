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
This is intended for usage in .NET Core projects. For further examples see the [tests](https://github.com/mattosaurus/PgpCore/tree/master/PgpCore.Tests/UnitTests).

```C#
using (PGP pgp = new PGP())
{
                // Generate keys
                pgp.GenerateKey(@"C:\TEMP\keys\public.asc", @"C:\TEMP\keys\private.asc", "email@email.com", "password");
                // Encrypt file
                pgp.EncryptFile(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted.pgp", @"C:\TEMP\keys\public.asc", true, true);
		// Encrypt file with multiple keys
		string[] publicKeys = Directory.GetFiles("C:\TEMP\keys\", "*.asc);
                pgp.EncryptFile(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted.pgp", publicKeys, true, true);
                // Encrypt and sign file
                pgp.EncryptFileAndSign(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted_signed.pgp", @"C:\TEMP\keys\public.asc", @"C:\TEMP\keys\private.asc", "password", true, true);
                // Decrypt file
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted.pgp", @"C:\TEMP\keys\content__decrypted.txt", @"C:\TEMP\keys\private.asc", "password");
                // Decrypt signed file
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted_signed.pgp", @"C:\TEMP\keys\content__decrypted_signed.txt", @"C:\TEMP\keys\private.asc", "password");

                // Encrypt stream
                using (FileStream inputFileStream = new FileStream(@"C:\TEMP\keys\content.txt", FileMode.Open))
                using (Stream outputFileStream = File.Create(@"C:\TEMP\keys\content__encrypted2.pgp"))
                using (Stream publicKeyStream = new FileStream(@"C:\TEMP\keys\public.asc", FileMode.Open))
                    pgp.EncryptStream(inputFileStream, outputFileStream, publicKeyStream, true, true);

                // Decrypt stream
                using (FileStream inputFileStream = new FileStream(@"C:\TEMP\keys\content__encrypted2.pgp", FileMode.Open))
                using (Stream outputFileStream = File.Create(@"C:\TEMP\keys\content__decrypted2.txt"))
                using (Stream privateKeyStream = new FileStream(@"C:\TEMP\keys\private.asc", FileMode.Open))
                    pgp.DecryptStream(inputFileStream, outputFileStream, privateKeyStream, "password");
}
```

A good resource for generating keys and messages is <a href="https://wp2pgpmail.com/pgp-key-generator/" alt="PGP Key Generator">PGP Key Generator</a>.
