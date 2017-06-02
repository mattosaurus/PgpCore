using System;
using PgpCore;

namespace PgpCoreTest
{
    class Program
    {
        static void Main(string[] args)
        {
            using (PGP pgp = new PGP())
            {
                pgp.EncryptFile(@"C:\TEMP\keys\content.txt", @"C:\TEMP\keys\content__encrypted.txt", @"C:\TEMP\keys\public.txt", true, true);
                pgp.DecryptFile(@"C:\TEMP\keys\content__encrypted.txt", @"C:\TEMP\keys\content__decrypted.txt", @"C:\TEMP\keys\private.txt", "password");
            }
        }
    }
}