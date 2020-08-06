using System;

namespace PgpCore
{
    public interface IPGPSign : IDisposable
    {
        void SignFile(string inputFilePath, string outputFilePath,
            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true, string name = "name");
    }
}