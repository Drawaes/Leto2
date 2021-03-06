using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using Leto.ConnectionStates;
using Leto.RecordLayer;

namespace Leto
{
    public abstract class SecurePipeConnection : IPipeConnection
    {
        private IPipe _inputPipe;
        private IPipe _outputPipe;
        private IPipe _handshakeInput;
        private IPipe _handshakeOutput;
        private IPipeConnection _connection;
        private IConnectionState _state;
        private SecurePipeOptions _securePipeOptions;
        private TaskCompletionSource<SecurePipeConnection> _handshakeComplete = new TaskCompletionSource<SecurePipeConnection>();

        internal SecurePipeConnection(IPipeConnection connection, SecurePipeOptions securePipeOptions, IConnectionState connectionState)
        {
            RecordHandler = new GeneralRecordHandler(null, TlsVersion.Tls1, connection.Output);
            _securePipeOptions = securePipeOptions;
            _inputPipe = new Pipe(securePipeOptions.PipeOptions);
            _outputPipe = new Pipe(securePipeOptions.PipeOptions);
            _connection = connection;
            _state = connectionState;
            _state.Connection = this;
            _handshakeInput = new Pipe(securePipeOptions.PipeOptions);
            _handshakeOutput = new Pipe(securePipeOptions.PipeOptions);
            RecordHandler = new GeneralRecordHandler(_state, TlsVersion.Tls12, _connection.Output);
            var ignore = ReadingLoop();
        }

        public IPipeReader Input => _outputPipe.Reader;
        public IPipeWriter Output => _inputPipe.Writer;
        public Task<SecurePipeConnection> HandshakeAwaiter => _handshakeComplete.Task;
        internal SecurePipeOptions Listener => _securePipeOptions;
        internal IPipeConnection Connection => _connection;
        internal IPipe HandshakeInput => _handshakeInput;
        internal IPipe HandshakeOutput => _handshakeOutput;
        internal IConnectionState State => _state;
        internal RecordHandler RecordHandler { get; set; }

        private async Task ReadingLoop()
        {
            try
            {
                if(_state.ProcessHandshake())
                {
                    var w = _connection.Output.Alloc();
                    await w.FlushAsync();
                }
                while (true)
                {
                    var result = await _connection.Input.ReadAsync();
                    var buffer = result.Buffer;
                    if (buffer.IsEmpty && result.IsCompleted)
                    {
                        _connection.Input.Advance(buffer.End);
                        return;
                    }
                    try
                    {
                        while (RecordHandler.ReadRecord(ref buffer, out var messageBuffer) == RecordState.Record)
                        {
                            switch (RecordHandler.CurrentRecordType)
                            {
                                case RecordType.Handshake:
                                    var handshakeWriter = _handshakeInput.Writer.Alloc();
                                    handshakeWriter.Append(messageBuffer);
                                    handshakeWriter.Commit();
                                    if (_state.ProcessHandshake())
                                    {
                                        var w = _connection.Output.Alloc();
                                        await w.FlushAsync();
                                    }
                                    if (_state.HandshakeComplete)
                                    {
                                        var ignore = ReadingApplicationDataLoop();
                                        _handshakeComplete.TrySetResult(this);
                                    }
                                    break;
                                case RecordType.Application:
                                    if (!_state.HandshakeComplete)
                                    {
                                        Alerts.AlertException.ThrowUnexpectedMessage(RecordType.Application);
                                    }
                                    var applicationWriter = _outputPipe.Writer.Alloc();
                                    applicationWriter.Append(messageBuffer);
                                    await applicationWriter.FlushAsync();
                                    break;
                                case RecordType.ChangeCipherSpec:
                                    _state.ChangeCipherSpec();
                                    break;
                                case RecordType.Alert:
                                    if (buffer.ReadBigEndian<byte>() == 0)
                                    {
                                        return;
                                    }
                                    throw new Alerts.AlertException(buffer);
                                default:
                                    Alerts.AlertException.ThrowUnexpectedMessage(RecordHandler.CurrentRecordType);
                                    break;
                            }
                        }
                    }
                    catch (Alerts.AlertException alert)
                    {
                        if (!alert.ReceivedFromPeer)
                        {
                            await RecordHandler.WriteAlert(alert);
                            _handshakeComplete.TrySetResult(this);
                        }
                        return;
                    }
                    finally
                    {
                        _connection.Input.Advance(buffer.Start, buffer.End);
                    }
                }
            }
            finally
            {
                _inputPipe.Reader.Complete();
                CloseHandshakePipes();
                Dispose();
            }
        }

        private async Task ReadingApplicationDataLoop()
        {
            try
            {
                while (true)
                {
                    var result = await _inputPipe.Reader.ReadAsync();
                    if (result.Buffer.IsEmpty && result.IsCompleted)
                    {
                        await RecordHandler.WriteAlert(new Alerts.AlertException(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.close_notify, "Application closed connection"));
                        return;
                    }
                    var buffer = result.Buffer;
                    try
                    {
                        await RecordHandler.WriteRecordsAndFlush(ref buffer, RecordType.Application);
                    }
                    finally
                    {
                        if (buffer.Length == 0)
                        {
                            _inputPipe.Reader.Advance(buffer.End);
                        }
                        else
                        {
                            _inputPipe.Reader.Advance(buffer.Start, buffer.End);
                        }
                    }
                }
            }
            finally
            {
                _outputPipe.Writer.Complete();
                CloseHandshakePipes();
                Dispose();
            }
        }

        private void CloseHandshakePipes()
        {
            _handshakeInput.Reader.Complete();
            _handshakeInput.Writer.Complete();
            _handshakeOutput.Reader.Complete();
            _handshakeOutput.Writer.Complete();
        }

        public void Dispose()
        {
            _connection?.Dispose();
            _connection = null;
            _state.Dispose();
        }
    }
}
