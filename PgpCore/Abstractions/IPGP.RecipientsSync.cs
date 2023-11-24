using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PgpCore.Abstractions
{
    public interface IRecipientsSync : IDisposable
    {
        IEnumerable<long> GetRecipients(FileInfo inputFileInfo);
        IEnumerable<long> GetRecipients(Stream inputStream);
        IEnumerable<long> GetRecipients(string input);

        IEnumerable<long> GetFileRecipients(FileInfo inputFileInfo);
        IEnumerable<long> GetStreamRecipients(Stream inputStream);
        IEnumerable<long> GetArmoredStringRecipients(string input);
    }
}
