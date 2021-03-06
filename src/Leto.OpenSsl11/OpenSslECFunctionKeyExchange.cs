using Leto.KeyExchanges;
using System;
using Leto.Hashes;
using static Leto.Interop.LibCrypto;
using Leto.Certificates;
using System.Buffers;
using Leto.Internal;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslECFunctionKeyExchange : IKeyExchange
    {
        private int _nid;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private EVP_PKEY _peerKey;
        private EVP_PKEY _keyPair;

        public OpenSslECFunctionKeyExchange(NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
            switch (namedGroup)
            {
                case NamedGroup.x25519:
                    _keyExchangeSize = 32;
                    _nid = OBJ_sn2nid("X25519");
                    break;
                case NamedGroup.x448:
                    _keyExchangeSize = 56;
                    _nid = OBJ_sn2nid("X448");
                    break;
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    break;
            }
        }

        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;
        public bool RequiresServerKeyExchange => true;

        public int ClientSendSize => _keyExchangeSize;

        public void PublicKeySpan(Span<byte> span)
        {
            GenerateKeyPair();
            var size = EVP_PKEY_get1_tls_encodedpoint(_keyPair, span);
        }

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            var tempBuffer = new byte[_keyExchangeSize];
            var secretSize = EVP_PKEY_derive(_keyPair, _peerKey, tempBuffer);
            var secretSpan = tempBuffer.Slice(0, secretSize);
            hashProvider.Tls12Prf(hashType, secretSpan, TlsConstants.Tls12.Label_MasterSecret, seed, output);
            System.Diagnostics.Debug.WriteLine(BitConverter.ToString(output.ToArray()));
        }

        public void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = peerKey.ReadVector<byte>();
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, $"The peer key is not the length of the keyexchange size {peerKey.Length} - {_keyExchangeSize}");
            }
            InternalSetPeerKey(peerKey.ToSpan());
        }

        private void InternalSetPeerKey(Span<byte> peerKey)
        {
            _peerKey = EVP_PKEY_new();
            EVP_PKEY_set_type(_peerKey, _nid);
            EVP_PKEY_set1_tls_encodedpoint(_peerKey, peerKey);
            GenerateKeyPair();
        }

        private void GenerateKeyPair()
        {
            if (_keyPair.IsValid) return;
            EVP_PKEY_keygen_function(_nid, out _keyPair);
        }

        public void Dispose()
        {
            _keyPair.Free();
            _peerKey.Free();
            GC.SuppressFinalize(this);
        }

        public void SetCertificate(ICertificate certificate)
        {
        }

        public void ClientSendKey(ref WriterWrapper writer)
        {
            writer.WriteBigEndian((byte)ClientSendSize);
            Span<byte> span = stackalloc byte[ClientSendSize];
            PublicKeySpan(span);
            writer.Write(span);
        }

        ~OpenSslECFunctionKeyExchange()
        {
            Dispose();
        }
    }
}
