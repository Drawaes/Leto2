using Leto.Certificates;
using Leto.Hashes;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Internal;

namespace Leto.KeyExchanges
{
    public class RsaKeyExchange : IKeyExchange
    {
        private byte[] _premasterSecret;
        private ICertificate _certificate;

        public bool HasPeerKey => false;
        public bool RequiresServerKeyExchange => false;
        public int KeyExchangeSize => 0;

        public NamedGroup NamedGroup => NamedGroup.None;

        public int ClientSendSize => _certificate.SignatureSize;

        public void PublicKeySpan(Span<byte> span) => throw new NotSupportedException();

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output) =>
            hashProvider.Tls12Prf(hashType, _premasterSecret, TlsConstants.Tls12.Label_MasterSecret, seed, output);
                
        public void Dispose()
        {
            //Nothing to cleanup in the case of a basic key exchange
        }

        public void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = peerKey.ReadVector<ushort>();
            var decryptedLength = certificate.Decrypt(scheme, peerKey.ToSpan(), peerKey.ToSpan());
            peerKey = peerKey.TakeSlice(decryptedLength);
            _premasterSecret = peerKey.ToArray();
        }
        public void SetPeerKey(BigEndianAdvancingSpan peerKey) => throw new NotSupportedException();

        public void SetCertificate(ICertificate certificate) => _certificate = certificate;

        public void ClientSendKey(ref WriterWrapper writer) => throw new NotImplementedException();
    }
}
