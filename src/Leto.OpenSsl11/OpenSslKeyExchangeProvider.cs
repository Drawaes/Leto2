using Leto.KeyExchanges;
using System;
using Leto.Internal;
using System.Collections.Generic;
using System.Linq;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslKeyExchangeProvider : IKeyExchangeProvider
    {
        private List<NamedGroup> _supportedNamedGroups = new List<NamedGroup>()
        {
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072,
            NamedGroup.ffdhe4096,
            NamedGroup.ffdhe6144,
            NamedGroup.ffdhe8192,
            NamedGroup.ffdhe8192,
            NamedGroup.secp256r1,
            NamedGroup.secp384r1,
            NamedGroup.secp521r1,
            NamedGroup.x25519,
            NamedGroup.x448
        };
        private NamedGroup DefaultNamedGroup { get; set; } = NamedGroup.secp521r1;

        public void SetSupportedNamedGroups(params NamedGroup[] namedGroups) => _supportedNamedGroups = namedGroups.ToList();
        
        /// <summary>
        /// Heritage KeyExchange selection (pre tls 1.3)
        /// </summary>
        /// <param name="keyExchange"></param>
        /// <param name="supportedGroups"></param>
        /// <returns></returns>
        public IKeyExchange GetKeyExchange(KeyExchangeType keyExchange, BigEndianAdvancingSpan supportedGroups)
        {
            switch (keyExchange)
            {
                case KeyExchangeType.Rsa:
                    return new RsaKeyExchange();
                case KeyExchangeType.Ecdhe:
                    return EcdheKeyExchange(supportedGroups);
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
                    return null;
            }
        }

        private IKeyExchange EcdheKeyExchange(BigEndianAdvancingSpan supportedGroups)
        {
            if(supportedGroups.Length == 0)
            {
                return GetEcdheKeyExchange(DefaultNamedGroup);
            }
            supportedGroups = supportedGroups.ReadVector<ushort>();
            while (supportedGroups.Length > 0)
            {
                var namedGroup = supportedGroups.Read<NamedGroup>();
                if (!_supportedNamedGroups.Contains(namedGroup))
                {
                    continue;
                }
                var key = GetEcdheKeyExchange(namedGroup);
                if (key != null) return key;
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
            return null;
        }

        private IKeyExchange GetEcdheKeyExchange(NamedGroup namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.secp256r1:
                case NamedGroup.secp384r1:
                case NamedGroup.secp521r1:
                    return new OpenSslECCurveKeyExchange(namedGroup);
                case NamedGroup.x25519:
                case NamedGroup.x448:
                    return new OpenSslECFunctionKeyExchange(namedGroup);
            }
            return null;
        }

        public void Dispose()
        {
            //No resources currently to clean up
        }
    }
}
