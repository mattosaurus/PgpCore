using PgpCore.Models;
using System;
using System.IO;

namespace PgpCore.Abstractions
{
    public interface IInspectSync : IDisposable
    {
        PGPInspectResult Inspect(Stream stream);
    }
}
