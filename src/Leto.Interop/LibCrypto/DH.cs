using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct DH
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (!IsValid) return;
                DH_free(_ptr);
                _ptr = IntPtr.Zero;
            }

            public override bool Equals(object obj)
            {
                if(obj is DH dh)
                {
                    return this == dh;
                }
                return false;
            }

            public override int GetHashCode() => _ptr.GetHashCode();

            public static bool operator ==(DH left, DH right) => left._ptr == right._ptr;

            public static bool operator !=(DH left, DH right) => !(left == right);
        }
    }
}
