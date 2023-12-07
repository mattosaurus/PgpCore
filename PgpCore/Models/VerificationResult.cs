using System;
using System.Collections.Generic;
using System.Text;

namespace PgpCore.Models
{
    public struct VerificationResult
    {
        public bool IsVerified { get; private set; }
        public string ClearText { get; private set; }

        public VerificationResult(bool isVerified, string clearText)
        {
            IsVerified = isVerified;
            ClearText = clearText;
        }
    }
}
