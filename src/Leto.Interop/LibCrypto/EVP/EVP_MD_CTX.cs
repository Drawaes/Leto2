using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct EVP_MD_CTX
        {
            private IntPtr _ptr;

            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
                EVP_MD_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }

            public override bool Equals(object obj)
            {
                if (obj is EVP_MD_CTX evp)
                {
                    return this == evp;
                }
                return true;
            }

            public override int GetHashCode() => _ptr.GetHashCode();

            public static bool operator ==(EVP_MD_CTX left, EVP_MD_CTX right) => left._ptr == right._ptr;

            public static bool operator !=(EVP_MD_CTX left, EVP_MD_CTX right) => !(left == right);
        }
    }
}
