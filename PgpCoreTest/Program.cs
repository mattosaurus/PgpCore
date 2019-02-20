using PgpCore;
using System;
using System.IO;
using System.Text;

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
                pgp.GenerateKey(@"C:\TEMP\keys\public2.asc", @"C:\TEMP\keys\private2.asc", "email@email.com", "password2");
                // Encrypt file
                pgp.EncryptFile(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted.pgp", @"C:\TEMP\keys\public.asc", true, true);
                // Encrypt file with multiple keys
                string[] publicKeys = { @"C:\TEMP\keys\public.asc", @"C:\TEMP\keys\public2.asc" };
                pgp.EncryptFile(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted_multiple.pgp", publicKeys, true, true);
                // Encrypt and sign file
                pgp.EncryptFileAndSign(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted_signed.pgp", @"C:\TEMP\keys\public.asc", @"C:\TEMP\keys\private.asc", "password", true, true);
                // Encrypt and sign multiple file
                pgp.EncryptFileAndSign(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted_signed_multiple.pgp", publicKeys, @"C:\TEMP\keys\private.asc", "password", true, true);
                // Decrypt file
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted.pgp", @"C:\TEMP\keys\content__decrypted.txt", @"C:\TEMP\keys\private.asc", "password");
                // Decrypt multiple file
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted_multiple.pgp", @"C:\TEMP\keys\content__decrypted_multiple.txt", @"C:\TEMP\keys\private.asc", "password");
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted_multiple.pgp", @"C:\TEMP\keys\content__decrypted_multiple2.txt", @"C:\TEMP\keys\private2.asc", "password2");
                // Decrypt signed file
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted_signed.pgp", @"C:\TEMP\keys\content__decrypted_signed.txt", @"C:\TEMP\keys\private.asc", "password");
                // Decrypt signed multiple file
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted_signed_multiple.pgp", @"C:\TEMP\keys\content__decrypted_signed_multiple.txt", @"C:\TEMP\keys\private.asc", "password");
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted_signed_multiple.pgp", @"C:\TEMP\keys\content__decrypted_signed_multiple2.txt", @"C:\TEMP\keys\private2.asc", "password2");

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

                // Encrypt and decrypt streams
                using (Stream inputFileStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("Streaming test message")))
                {
                    using (Stream publicKeyStream = new FileStream(@"C:\TEMP\keys\public.asc", FileMode.Open))
                    {
                        using (Stream encryptedMemoryStream = new MemoryStream())
                        {
                            pgp.EncryptStream(inputFileStream, encryptedMemoryStream, publicKeyStream);
                            encryptedMemoryStream.Seek(0, SeekOrigin.Begin);
                            StreamReader encryptedReader = new StreamReader(encryptedMemoryStream);
                            // Reset stream to beginning
                            encryptedMemoryStream.Seek(0, SeekOrigin.Begin);
                            string encryptedText = encryptedReader.ReadToEnd();
                            Console.WriteLine(encryptedText);

                            // Reset stream to beginning again
                            // Only necessary as stream read to end above for demo output
                            encryptedMemoryStream.Seek(0, SeekOrigin.Begin);

                            using (Stream decryptedMemoryStream = new MemoryStream())
                            {
                                using (Stream privateKeyStream = new FileStream(@"C:\TEMP\keys\private.asc", FileMode.Open))
                                {
                                    pgp.DecryptStream(encryptedMemoryStream, decryptedMemoryStream, privateKeyStream, "password");
                                    decryptedMemoryStream.Seek(0, SeekOrigin.Begin);
                                    StreamReader decryptedReader = new StreamReader(decryptedMemoryStream);
                                    string decryptedText = decryptedReader.ReadToEnd();
                                    Console.WriteLine(decryptedText);
                                }
                            }
                        }
                    }
                }

                // Encrypt key and sign stream
                using (Stream inputFileStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("Streaming signed test message")))
                {
                    using (Stream publicKeyStream = new FileStream(@"C:\TEMP\keys\public.asc", FileMode.Open))
                    {
                        using (Stream privateKeyStream = new FileStream(@"C:\TEMP\keys\private.asc", FileMode.Open))
                        {
                            using (Stream encryptedMemoryStream = new MemoryStream())
                            {
                                pgp.EncryptStreamAndSign(inputFileStream, encryptedMemoryStream, publicKeyStream, privateKeyStream, "password");
                                // Reset stream to beginning
                                encryptedMemoryStream.Seek(0, SeekOrigin.Begin);
                                StreamReader encryptedReader = new StreamReader(encryptedMemoryStream);
                                string encryptedText = encryptedReader.ReadToEnd();
                                Console.WriteLine(encryptedText);
                            }
                        }
                    }
                }
            }
        }
    }
}
