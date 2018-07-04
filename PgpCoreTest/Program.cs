using PgpCore;
using System;
using System.IO;

namespace PgpCoreTest
{
    class Program
    {
        static void Main(string[] args)
        {
            using (PGP pgp = new PGP())
            {
                // Generate keys
                pgp.GenerateKey(@"C:\TEMP\keys\public.asc", @"C:\TEMP\keys\private.asc", "email@email.com", "password");
                // Encrypt file
                pgp.EncryptFile(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted.pgp", @"C:\TEMP\keys\public.asc", true, true);
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
        }
    }
}
