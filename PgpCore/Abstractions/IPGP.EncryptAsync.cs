using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Abstractions
{
    public interface IEncryptAsync : IDisposable
    {
        Task EncryptAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task EncryptAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task<string> EncryptAsync(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task EncryptAndSignAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task EncryptAndSignAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task<string> EncryptAndSignAsync(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);

        Task EncryptFileAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task EncryptStreamAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task<string> EncryptArmoredStringAsync(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task EncryptFileAndSignAsync(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        Task<string> EncryptArmoredStringAndSignAsync(string input, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
    }
}