namespace Leto.Handshake
{
    public enum HandshakeState
    {
        WaitingForClientHello,
        WaitingForClientKeyExchange,
        WaitingForChangeCipherSpec,
        WaitingForClientFinished,
        HandshakeCompleted,
        WaitingForClientFinishedAbbreviated,
        WaitingHelloRetry,
        WaitingForServerHello,
        WaitingForServerCertificate,
        WaitingForServerKeyExchange,
        WaitingForServerHelloDone,
        WaitingForServerFinished
    }
}
