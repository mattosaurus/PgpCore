using PgpCore.Models;
using System;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IInspectAsync : IDisposable
    {
        Task<PGPInspectResult> InspectAsync(Stream inputStream);
        Task<PGPInspectResult> InspectAsync(FileInfo inputFile);
        Task<PGPInspectResult> InspectAsync(string input);
    }
}
