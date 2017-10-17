using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Leto.ProtocolFacts
{
    public class RsaKeyExchangeFacts
    {
        [Fact]
        public void CheckSetPeerKeyNotSupported()
        {
            var exchange = new KeyExchanges.RsaKeyExchange();
            Assert.Throws<NotSupportedException>(() =>
                {
                    exchange.SetPeerKey(default);
                });
        }

        [Fact]
        public void WritePublicKeyNotSupported()
        {
            var exchange = new KeyExchanges.RsaKeyExchange();
            Assert.Throws<NotSupportedException>(() =>
            {
                exchange.PublicKeySpan(default);
            });
        }
    }
}
