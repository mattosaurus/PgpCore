using System;

namespace PgpCore
{
    public interface IPGPSign : IDisposable
    {
        void SignFile(string inputFilePath, string outputFilePath,
            string privateKeyFilePath, string passPhrase, bool armor, bool withIntegrityCheck, string name);
    }
}