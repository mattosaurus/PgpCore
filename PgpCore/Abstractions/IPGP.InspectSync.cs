using PgpCore.Models;
using System;
using System.IO;

namespace PgpCore.Abstractions
{
    public interface IInspectSync : IDisposable
    {
        PgpInspectResult Inspect(Stream inputStream);
        PgpInspectResult Inspect(FileInfo inputFile);
        PgpInspectResult Inspect(string input);
    }
}
