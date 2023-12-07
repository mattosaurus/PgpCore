using PgpCore.Models;
using System;
using System.IO;

namespace PgpCore.Abstractions
{
    public interface IInspectSync : IDisposable
    {
        PGPInspectResult Inspect(Stream inputStream);
        PGPInspectResult Inspect(FileInfo inputFile);
        PGPInspectResult Inspect(string input);
    }
}
