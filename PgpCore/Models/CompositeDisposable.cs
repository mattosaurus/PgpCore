using System;
using System.Collections.Concurrent;

namespace PgpCore.Models
{
    /// <seealso href="https://github.com/dotnet/reactive/blob/main/Rx.NET/Source/src/System.Reactive/Disposables/CompositeDisposable.cs">
    /// Simplified adaptation from System.Reactive.
    /// </seealso>
    internal sealed class CompositeDisposable : IDisposable
    {
        private readonly ConcurrentQueue<IDisposable> _disposables = new ConcurrentQueue<IDisposable>();

        public void Add(IDisposable disposable)
        {
            if (disposable == null)
                throw new ArgumentNullException(nameof(disposable));

            _disposables.Enqueue(disposable);
        }

        public void Dispose()
        {
            while (_disposables.TryDequeue(out IDisposable disposable))
                disposable.Dispose();
        }
    }
}
