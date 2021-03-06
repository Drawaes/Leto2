using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe void* HMAC(EVP_HashType evp_md, void* key, int key_len, void* d, int n, void* md, ref int md_len);

        public unsafe static int HMAC(EVP_HashType evp, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> output)
        {
            fixed(void* keyPtr = &key.DangerousGetPinnableReference())
            fixed(void* dataPtr = &data.DangerousGetPinnableReference())
            fixed(void* outputPtr = &output.DangerousGetPinnableReference())
            {
                var outputLength = output.Length;
                var result = HMAC(evp, keyPtr, key.Length, dataPtr, data.Length, outputPtr, ref outputLength);
                ThrowOnNullPointer(result);
                return outputLength;
            }
        }
    }
}
