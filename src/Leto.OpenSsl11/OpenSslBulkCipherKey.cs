using Leto.BulkCiphers;
using Leto.Internal;
using System;
using System.Buffers;
using static Leto.Interop.LibCrypto;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslBulkCipherKey : ISymmetricalCipher
    {
        private EVP_CIPHER_CTX _ctx;
        private Memory<byte> _key;
        private Memory<byte> _iv;
        private readonly EVP_BulkCipher_Type _type;
        private readonly int _tagSize;
        private OwnedMemory<byte> _keyStore;

        internal OpenSslBulkCipherKey(EVP_BulkCipher_Type type, OwnedMemory<byte> keyStore, int keySize, int ivSize, int tagSize)
        {
            _tagSize = tagSize;
            _keyStore = keyStore;
            _key = _keyStore.Memory.Slice(0, keySize);
            _iv = _keyStore.Memory.Slice(keySize, ivSize);
            _type = type;
            _ctx = EVP_CIPHER_CTX_new();
        }

        public Memory<byte> IV => _iv;
        public int TagSize => _tagSize;

        public void Init(Leto.BulkCiphers.KeyMode mode) => EVP_CipherInit_ex(_ctx, _type, _key.Span, _iv.Span, (Leto.Interop.LibCrypto.KeyMode)mode);
        public int Update(Span<byte> input, Span<byte> output) => EVP_CipherUpdate(_ctx, output, input);
        public int Update(Span<byte> inputAndOutput) => EVP_CipherUpdate(_ctx, inputAndOutput);
        public unsafe void AddAdditionalInfo(ref AdditionalInfo addInfo)
        {
            fixed (void* ptr = &addInfo)
            {
                var s = new Span<byte>(ptr, sizeof(AdditionalInfo));
                var output = new Span<byte>();
                EVP_CipherUpdate(_ctx, output, s);
            }
        }

        public void GetTag(Span<byte> span)
        {
            if (span.Length < _tagSize)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException());
            }
            EVP_CIPHER_CTX_GetTag(_ctx, span);
        }

        public void SetTag(ReadOnlySpan<byte> tagSpan) => EVP_CIPHER_CTX_SetTag(_ctx, tagSpan);

        public void Dispose()
        {
            _keyStore.Dispose();
            _ctx.Free();
            GC.SuppressFinalize(this);
        }

        public int Finish(Span<byte> inputAndOutput)
        {
            var bytesWritten = 0;
            if (inputAndOutput.Length > 0)
            {
                bytesWritten = Update(inputAndOutput);
            }
            EVP_CipherFinal_ex(_ctx);
            return bytesWritten;
        }

        public int Finish(Span<byte> input, Span<byte> output)
        {
            var bytesWritten = 0;
            if (input.Length > 0)
            {
                bytesWritten = Update(input, output);
            }
            EVP_CipherFinal_ex(_ctx);
            return bytesWritten;
        }

        ~OpenSslBulkCipherKey() => Dispose();
    }
}
