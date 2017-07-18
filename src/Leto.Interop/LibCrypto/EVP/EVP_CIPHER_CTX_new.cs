using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public static extern EVP_CIPHER_CTX EVP_CIPHER_CTX_new();
    }
}
