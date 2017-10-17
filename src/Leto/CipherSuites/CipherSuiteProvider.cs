using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Leto.Internal;
using static Leto.BufferExtensions;

namespace Leto.CipherSuites
{
    public class CipherSuiteProvider
    {
        private CipherSuite[] _cipherSuites;
        private byte[] _cipherSuitesBuffer;

        public CipherSuiteProvider(CipherSuite[] cipherSuites)
        {
            _cipherSuites = cipherSuites;
            GenerateCipherSuiteBuffer();
        }

        private void GenerateCipherSuiteBuffer()
        {
            var size = _cipherSuites.Length * Unsafe.SizeOf<ushort>();
            _cipherSuitesBuffer = new byte[size + Unsafe.SizeOf<ushort>()];
            var span = new BigEndianAdvancingSpan((Span<byte>)_cipherSuitesBuffer);
            span.Write((ushort)size);
            for (var i = 0; i < _cipherSuites.Length; i++)
            {
                span.Write(_cipherSuites[i].Code);
            }
            Debug.Assert(span.Length == 0);
        }

        public CipherSuite GetCipherSuite(ushort cipherSuite)
        {
            for (var i = 0; i < _cipherSuites.Length; i++)
            {
                if (_cipherSuites[i].Code == cipherSuite)
                {
                    return _cipherSuites[i];
                }
            }
            return null;
        }

        public CipherSuite GetCipherSuite(TlsVersion tlsVersion, BigEndianAdvancingSpan cipherSuites)
        {
            for (var x = 0; x < _cipherSuites.Length; x++)
            {
                var tempSpan = cipherSuites;
                while (tempSpan.Length > 0)
                {
                    var cipherSuite = tempSpan.Read<ushort>();
                    if (cipherSuite == _cipherSuites[x].Code)
                    {
                        if (_cipherSuites[x].SupportsVersion(tlsVersion))
                        {
                            return _cipherSuites[x];
                        }
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match cipher suites");
            return null;
        }

        public void SetCipherSuites(CipherSuite[] cipherSuites)
        {
            _cipherSuites = cipherSuites;
            GenerateCipherSuiteBuffer();
        }

        internal CipherSuite GetCipherSuite(TlsVersion tlsVersion, ushort cipherSuite)
        {
            for(var x = 0; x < _cipherSuites.Length;x++)
            {
                if(cipherSuite == _cipherSuites[x].Code)
                {
                    if(_cipherSuites[x].SupportsVersion(tlsVersion))
                    {
                        return _cipherSuites[x];
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match cipher suites");
            return null;
        }

        internal ReadOnlySpan<byte> GetCipherSuites() => (ReadOnlySpan<byte>)_cipherSuitesBuffer;
        internal int CipherSuitesSize => _cipherSuitesBuffer.Length;
    }
}
