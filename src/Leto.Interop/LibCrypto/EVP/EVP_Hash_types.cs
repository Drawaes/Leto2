using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        public static readonly EVP_HashType EVP_sha256 = Internal_EVP_sha256();
        public static readonly EVP_HashType EVP_sha384 = Internal_EVP_sha384();
        public static readonly EVP_HashType EVP_sha512 = Internal_EVP_sha512();

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_sha256")]
        private static extern EVP_HashType Internal_EVP_sha256();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_sha384")]
        private static extern EVP_HashType Internal_EVP_sha384();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_sha512")]
        private static extern EVP_HashType Internal_EVP_sha512();

        [StructLayout(LayoutKind.Sequential)]
        public struct EVP_HashType
        {
            private IntPtr _ptr;
        }
    }
}
