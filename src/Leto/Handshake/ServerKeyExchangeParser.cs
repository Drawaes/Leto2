using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Text;
using Leto.Certificates;
using Leto.Internal;
using Leto.KeyExchanges;

namespace Leto.Handshake
{
    public ref struct ServerKeyExchangeParser
    {
        private ECCurveType _curveType;
        private NamedGroup _namedGroup;
        private SignatureScheme _signatureScheme;
        private BigEndianAdvancingSpan _key;
        private Span<byte> _signature;
        private Span<byte> _data;

        public ServerKeyExchangeParser(ReadableBuffer reader)
        {
            var originalSpan = reader.ToSpan();
            var span = new BigEndianAdvancingSpan(originalSpan);
            span.Read<HandshakeHeader>();
            _curveType = span.Read<ECCurveType>();
            if (_curveType != ECCurveType.named_curve)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "We only support named curves");
            }

            _namedGroup = span.Read<NamedGroup>();
            _key = span;
            span.ReadVector<byte>();
            var dataLength = originalSpan.Length - span.Length;
            _data = originalSpan.Slice(4, dataLength - 4);

            _signatureScheme = span.Read<SignatureScheme>();
            _signature = span.ReadVector<ushort>().ToSpan();
            Debug.Assert(span.Length == 0);
        }

        public Span<byte> Signature => _signature;
        public Span<byte> Data => _data;
        public SignatureScheme SignatureScheme => _signatureScheme;
        public BigEndianAdvancingSpan Key => _key;
    }
}
