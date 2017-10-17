using Leto.Certificates;
using System;
using System.IO.Pipelines;
using Leto.Internal;
using System.Linq;

namespace Leto.Handshake
{
    public static class CertificateWriter
    {
        public static int GetCertificatesSize(ICertificate certificate)
        {
            var size = 3 * (certificate.CertificateChain.Length + 1);
            size += certificate.CertificateData.Length;
            size += certificate.CertificateChain.Sum(c => c.Length);
            return size;
        }

        public static void WriteCertificates(ref WriterWrapper buffer, ICertificate certificate)
        {
            var size = GetCertificatesSize(certificate);

            buffer.WriteBigEndian((UInt24)size);
            WriteCertificate(ref buffer, certificate.CertificateData);

            foreach(var b in certificate.CertificateChain)
            {
                WriteCertificate(ref buffer, b);
            }
        }

        private static void WriteCertificate(ref WriterWrapper writer, Span<byte> certData)
        {
            writer.WriteBigEndian((UInt24)certData.Length);
            writer.Write(certData);
        }
    }
}
