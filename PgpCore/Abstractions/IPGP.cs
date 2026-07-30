using System;
using System.Collections.Generic;
using System.Text;

namespace PgpCore.Abstractions
{
    public interface IPGP : IDecryptAsync, IDecryptSync, IEncryptAsync, IEncryptSync, IInspectAsync, IInspectSync, IKeyAsync, IKeySync, IRecipientsSync, ISignAsync, ISignSync, IDetachedSignAsync, IDetachedSignSync, IVerifyAsync, IVerifySync
    {
    }
}
