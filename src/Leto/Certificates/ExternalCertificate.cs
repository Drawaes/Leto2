using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Leto.Handshake;
using Leto.Hashes;
using Leto.Internal;

namespace Leto.Certificates
{
    public class ExternalCertificate : ICertificate
    {
        private X509Certificate2 _certificate;
        private X509Certificate2Collection _collection;
        private RSA _rsaPublicKey;
        private ECDsa _ecdsaPublicKey;
        private int _signatureSize;
        private CertificateType _certificateType;
        private SignatureScheme _signatureScheme;

        public ExternalCertificate(ReadableBuffer buffer)
        {
            var reader = new BigEndianAdvancingSpan(buffer.ToSpan());
            reader.Read<HandshakeHeader>();
            reader = reader.ReadVector<UInt24>();
            _certificate = new X509Certificate2(reader.ReadVector<UInt24>().ToArray());

            if (reader.Length > 0)
            {
                _collection = new X509Certificate2Collection();
                while (reader.Length > 0)
                {
                    var cert = new X509Certificate2(reader.ReadVector<UInt24>().ToArray());
                    _collection.Add(cert);
                }
            }
            Debug.Assert(reader.Length == 0);

            _rsaPublicKey = _certificate.GetRSAPublicKey();
            if (_rsaPublicKey != null)
            {
                _certificateType = CertificateType.rsa;
                _signatureSize = _rsaPublicKey.KeySize / 8;
                _certificateType = CertificateType.rsa;
                return;
            }
            _ecdsaPublicKey = _certificate.GetECDsaPublicKey();
            if (_ecdsaPublicKey != null)
            {
                _certificateType = CertificateType.ecdsa;
                switch (_ecdsaPublicKey.KeySize)
                {
                    case 256:
                        _signatureScheme = SignatureScheme.ecdsa_secp256r1_sha256;
                        _signatureSize = 72;
                        break;
                    case 384:
                        _signatureScheme = SignatureScheme.ecdsa_secp384r1_sha384;
                        throw new NotImplementedException();
                    case 521:
                        _signatureSize = 132;
                        _signatureScheme = SignatureScheme.ecdsa_secp521r1_sha512;
                        break;
                    default:
                        throw new InvalidOperationException($"Unsupported Ecdsa Keysize {_ecdsaPublicKey.KeySize}");
                }
                return;
            }
        }

        public CertificateType CertificateType => throw new NotImplementedException();
        public byte[] CertificateData => throw new NotImplementedException();
        public byte[][] CertificateChain => throw new NotImplementedException();
        public int SignatureSize => throw new NotImplementedException();

        public void CheckSignature(IHashProvider hashProvider, SignatureScheme signatureScheme, Span<byte> signature, Span<byte> data)
        {
            //Screwed at the moment.
            return;
            //var hashName = ManagedCertificate.GetHashName(signatureScheme);
            //if (_rsaPublicKey != null)
            //{
            //    var padding = ManagedCertificate.GetPaddingMode(signatureScheme);
            //    if(!_rsaPublicKey.VerifyData(data.ToArray(), signature.ToArray(), hashName, padding))
            //    {
            //        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Could not verify the signature");
            //    }
            //    return;
            //}
            //throw new NotImplementedException();
        }

        public int Decrypt(SignatureScheme scheme, Span<byte> encryptedData, Span<byte> output) => throw new NotImplementedException();

        public SignatureScheme SelectAlgorithm(BigEndianAdvancingSpan buffer) => throw new NotImplementedException();

        public ReadOnlySpan<byte> SignHash(IHashProvider provider, SignatureScheme scheme, Span<byte> message) => throw new NotImplementedException();

        public bool SupportsScheme(SignatureScheme scheme) => throw new NotImplementedException();
    }
}
