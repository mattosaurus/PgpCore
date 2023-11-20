using System;
using System.Collections.Generic;
using System.Text;

namespace PgpCore.Abstractions
{
    public interface IPGP : IDecryptAsync, IDecryptSync, IEncryptAsync, IEncryptSync, IKeyAsync, IKeySync, IRecipientsSync, ISignAsync, ISignSync, IVerifyAsync, IVerifySync
    {
    }
}
