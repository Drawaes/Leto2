using System;
using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Leto.Handshake;
using Leto.Hashes;
using Leto.Internal;
using static Leto.BufferExtensions;

namespace Leto.Certificates
{
    public class ManagedCertificate : ICertificate
    {
        private RSA _rsaPrivateKey;
        private ECDsa _ecdsaPrivateKey;
        private SignatureScheme _ecDsaSignatureScheme;
        private CertificateType _certificateType;
        private byte[] _certificateData;
        private byte[][] _certificateChain;
        private int _signatureSize;
                
        public ManagedCertificate(X509Certificate2 certificate, X509Certificate2Collection chain)
        {
            if (chain == null || chain.Count == 0)
            {
                _certificateChain = new byte[0][];
            }
            else
            {
                _certificateChain = new byte[chain.Count][];
                for (var i = 0; i < _certificateChain.Length; i++)
                {
                    _certificateChain[i] = chain[i].RawData;
                }
            }
            _rsaPrivateKey = certificate.GetRSAPrivateKey();
            if (_rsaPrivateKey != null)
            {
                _certificateType = CertificateType.rsa;
                _certificateData = certificate.RawData;
                _signatureSize = _rsaPrivateKey.KeySize / 8;
                return;
            }
            _ecdsaPrivateKey = certificate.GetECDsaPrivateKey();
            if (_ecdsaPrivateKey != null)
            {
                _certificateType = CertificateType.ecdsa;
                _certificateData = certificate.RawData;
                switch (_ecdsaPrivateKey.KeySize)
                {
                    case 256:
                        _ecDsaSignatureScheme = SignatureScheme.ecdsa_secp256r1_sha256;
                        _signatureSize = 72;
                        break;
                    case 384:
                        _ecDsaSignatureScheme = SignatureScheme.ecdsa_secp384r1_sha384;
                        throw new NotImplementedException();
                    case 521:
                        _signatureSize = 132;
                        _ecDsaSignatureScheme = SignatureScheme.ecdsa_secp521r1_sha512;
                        break;
                    default:
                        throw new InvalidOperationException($"Unsupported Ecdsa Keysize {_ecdsaPrivateKey.KeySize}");
                }
                return;
            }
            throw new CryptographicException("Unable to get a private key from the certificate");
        }

        public CertificateType CertificateType => _certificateType;
        public byte[] CertificateData => _certificateData;
        public byte[][] CertificateChain => _certificateChain;
        public int SignatureSize => _signatureSize;
        public SignatureScheme DefaultSignatureScheme { get; set; } = SignatureScheme.rsa_pkcs1_sha512;

        public void CheckSignature(IHashProvider hashProvider, SignatureScheme signatureScheme, Span<byte> signature, Span<byte> data)
        {
            throw new NotImplementedException();
        }

        public int Decrypt(SignatureScheme scheme, Span<byte> encryptedData, Span<byte> output)
        {
            if (_certificateType == CertificateType.rsa)
            {
                var padding = RSAEncryptionPadding.Pkcs1;
                var result = _rsaPrivateKey.Decrypt(encryptedData.ToArray(), padding);
                result.CopyTo(output);
                return result.Length;
            }
            throw new InvalidOperationException($"The {scheme} certificate type cannot be used to decrypt");
        }

        public SignatureScheme SelectAlgorithm(BigEndianAdvancingSpan buffer)
        {
            if (_certificateType == CertificateType.ecdsa)
            {
                return _ecDsaSignatureScheme;
            }
            if(buffer.Length == 0)
            {
                return DefaultSignatureScheme;
            }
            buffer = buffer.ReadVector<ushort>();
            while (buffer.Length > 0)
            {
                var scheme = buffer.Read<SignatureScheme>();
                var lastByte = 0x00FF & (ushort)scheme;
                switch (_certificateType)
                {
                    case CertificateType.rsa:
                        if (lastByte == 1)
                        {
                            return scheme;
                        }
                        if ((0xFF00 & (ushort)scheme) == 0x0800 && lastByte > 3 && lastByte < 7)
                        {
                            return scheme;
                        }
                        break;
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Failed to find an appropriate signature scheme");
            return SignatureScheme.none;
        }

        public ReadOnlySpan<byte> SignHash(IHashProvider provider, SignatureScheme scheme, Span<byte> message)
        {
            if (_certificateType == CertificateType.rsa)
            {
                var result = _rsaPrivateKey.SignData(message.ToArray(), GetHashName(scheme), GetPaddingMode(scheme));
                return new ReadOnlySpan<byte>(result);
            }
            else if (_certificateType == CertificateType.ecdsa)
            {
                var result = _ecdsaPrivateKey.SignData(message.ToArray(), GetHashName(scheme));
                return new ReadOnlySpan<byte>(result);
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Certificate signing failed");
            return default;
        }

        public bool SupportsScheme(SignatureScheme scheme)
        {
            if (_certificateType == CertificateType.ecdsa)
            {
                return scheme == _ecDsaSignatureScheme;
            }
            var lastByte = 0x00FF & (ushort)scheme;
            var firstByte = 0xFF00 & (ushort)scheme;
            if (lastByte == 0x0001 || firstByte == 0x0800)
            {
                return true;
            }
            return false;
        }

        internal static HashAlgorithmName GetHashName(SignatureScheme scheme)
        {
            switch (scheme)
            {
                case SignatureScheme.rsa_pkcs1_sha256:
                case SignatureScheme.rsa_pss_sha256:
                case SignatureScheme.ecdsa_secp256r1_sha256:
                    return HashAlgorithmName.SHA256;
                case SignatureScheme.ecdsa_secp384r1_sha384:
                case SignatureScheme.rsa_pkcs1_sha384:
                case SignatureScheme.rsa_pss_sha384:
                    return HashAlgorithmName.SHA384;
                case SignatureScheme.ecdsa_secp521r1_sha512:
                case SignatureScheme.rsa_pkcs1_sha512:
                case SignatureScheme.rsa_pss_sha512:
                    return HashAlgorithmName.SHA512;
            }
            throw new InvalidOperationException();
        }

        internal static RSASignaturePadding GetPaddingMode(SignatureScheme scheme)
        {
            switch (scheme)
            {
                case SignatureScheme.rsa_pkcs1_sha256:
                case SignatureScheme.rsa_pkcs1_sha384:
                case SignatureScheme.rsa_pkcs1_sha512:
                    return RSASignaturePadding.Pkcs1;
                case SignatureScheme.rsa_pss_sha256:
                case SignatureScheme.rsa_pss_sha384:
                case SignatureScheme.rsa_pss_sha512:
                    return RSASignaturePadding.Pss;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
