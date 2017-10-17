using Leto.Certificates;
using Leto.Hashes;
using System;
using Leto.Internal;

namespace Leto.KeyExchanges
{
    public interface IKeyExchange : IDisposable
    {
        bool RequiresServerKeyExchange { get; }
        void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme);
        int KeyExchangeSize { get; }
        void PublicKeySpan(Span<byte> span);
        NamedGroup NamedGroup { get; }
        void SetCertificate(ICertificate certificate);

        void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output);
        int ClientSendSize { get; }
        void ClientSendKey(ref WriterWrapper writer);
    }
}
