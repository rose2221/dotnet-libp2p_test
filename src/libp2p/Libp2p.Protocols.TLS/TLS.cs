using System.Buffers;
using System.Net;
using System.Net.Security;
using Nethermind.Libp2p.Protocols.Quic;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using Nethermind.Libp2p.Core;
using Multiformats.Address;
using Multiformats.Address.Protocols;
using System.Runtime.CompilerServices;

namespace Nethermind.Libp2p.Protocols;

public class TlsProtocol : IProtocol
{
    private readonly ILogger<TlsProtocol>? _logger;
    private readonly ECDsa _sessionKey;
    public SslApplicationProtocol? LastNegotiatedApplicationProtocol { get; private set; }
    private readonly List<SslApplicationProtocol> _protocols;

    public TlsProtocol(List<SslApplicationProtocol> protocols, ILoggerFactory? loggerFactory = null)
    {
        _logger = loggerFactory?.CreateLogger<TlsProtocol>();
        _sessionKey = ECDsa.Create();
        _protocols = protocols;
    }

    public string Id => "/tls/1.0.0";

//     public async Task InitializeTcpClient(IPeerContext context)
// {
//     // Extract Remote IP and Port from context.RemoteEndpoint (assuming it's Multiaddress)
//     Multiaddress remoteAddress = context.RemoteEndpoint;

//     string ipAddress = remoteAddress.Get<IP4>().ToString(); // or IP6 if IPv6 is used
//     int remotePort = int.Parse(remoteAddress.Get<TCP>().ToString());

//     // Optionally, you can extract the local address and port if needed (context.LocalEndpoint)
//     Multiaddress localAddress = context.LocalEndpoint;
//     string localIpAddress = localAddress.Get<IP4>().ToString(); // or IP6 if applicable
//     int localPort = int.Parse(localAddress.Get<TCP>().ToString());

//     // Now create a TcpClient and optionally bind it to a specific local address and port
//     TcpClient tcpClient = new TcpClient(new IPEndPoint(IPAddress.Parse(localIpAddress), localPort));

//     // Connect the TcpClient to the remote peer
//     await tcpClient.ConnectAsync(ipAddress, remotePort);

//     // Now tcpClient is ready to use
//     NetworkStream networkStream = tcpClient.GetStream();
    
//     // Optionally, create an SslStream if you are using TLS
//     SslStream sslStream = new SslStream(networkStream);

//     // Perform SSL/TLS handshake or proceed with communication
//     // Example: await sslStream.AuthenticateAsClientAsync("serverName");
// }

    public async Task ListenAsync(IChannel signalingChannel, IChannelFactory? channelFactory, IPeerContext context)
    {
        _logger?.LogDebug("Handling connection");
        if (channelFactory is null)
        {
            throw new ArgumentException("Protocol is not properly instantiated");
        }
// byte[] buffer = new byte[8192]; // Adjust buffer size as needed
//     MemoryStream memoryStream = new MemoryStream();
//     CancellationToken cancellationToken = CancellationToken.None;
//     var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); 
       
      



//     while (true)
//     {
//         ReadResult readResult = await signalingChannel.ReadAsync(buffer.Length, ReadBlockingMode.WaitAll, timeoutCts.Token);

//     // Extract data from ReadOnlySequence<byte> (readResult.Data)
//     ReadOnlySequence<byte> data = readResult.Data;

//     // Determine how many bytes were read
//     int bytesRead = (int)data.Length;

//     if (bytesRead == 0)
//     {
//         break; // Connection closed
//     }

//     // Write the data from ReadOnlySequence<byte> into the MemoryStream
//     foreach (var segment in data)
//     {
//         await memoryStream.WriteAsync(segment);
//     }
//     }

//     memoryStream.Position = 0; // Reset position for reading from the beginning
       
Socket connectedSocket = context.Socket;// existing connected socket;
// connectedSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
// Create a new TcpClient and assign the existing socket to it
TcpClient tcpClient = new TcpClient
{
    Client = connectedSocket // Assign the connected socket to TcpClient
};

    _logger?.LogDebug("Successfully received data from signaling channel.");

        while (true)
        {
            try
            {
          
                X509Certificate certificate = CertificateHelper.CertificateFromIdentity(_sessionKey, context.LocalPeer.Identity);

                SslServerAuthenticationOptions serverAuthenticationOptions = new()
                {
                    ApplicationProtocols = _protocols,
                    RemoteCertificateValidationCallback = (_, c, _, _) => VerifyRemoteCertificate(context.RemotePeer.Identity.PeerId.ToString(), c),
                    ServerCertificate = certificate,
                    ClientCertificateRequired = true,
                };

                // _logger?.LogDebug("Accepted new TCP client connection from {RemoteEndPoint}", tcpClient.Client.RemoteEndPoint);
                SslStream sslStream = new(tcpClient.GetStream(), false, serverAuthenticationOptions.RemoteCertificateValidationCallback);

                try
                {
                    await sslStream.AuthenticateAsServerAsync(serverAuthenticationOptions);
                }
                catch (Exception ex)
                {
                    _logger?.LogError("An error occurred during TLS authentication: {Message}", ex.Message);
                    _logger?.LogDebug("Exception details: {StackTrace}", ex.StackTrace);
                    throw;
                }

                if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http2)
                {
                    _logger?.LogDebug("HTTP/2 protocol negotiated");
                }
                else if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11)
                {
                    _logger?.LogDebug("HTTP/1.1 protocol negotiated");
                }
                else if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http3)
                {
                    _logger?.LogDebug("HTTP/3 protocol negotiated");
                }
                else
                {
                    _logger?.LogDebug("Unknown protocol negotiated");
                }

                IChannel upChannel = channelFactory.SubListen(context);
               await ProcessStreamsAsync(sslStream,  tcpClient, upChannel, context);

    // signalingChannel.GetAwaiter().OnCompleted(() =>
    // {
    //     memoryStream.Close();
    // });
    }
            catch (Exception ex)
            {
                _logger?.LogError("An unexpected exception occurred while accepting TCP client: {Message}", ex.Message);
                _logger?.LogDebug("Exception details: {StackTrace}", ex.StackTrace);
                break;
            }
        }
    }
    

    public async Task DialAsync(IChannel signalingChannel, IChannelFactory? channelFactory, IPeerContext context)
    {
        _logger?.LogInformation("Handling connection");
        //  await signalingChannel.WriteLineAsync("/multistream/1.0.0\n/tls/1.0.0");

       
        if (channelFactory is null)
        {
            throw new ArgumentException("Protocol is not properly instantiated");
        }
        // Initialize the buffer and MemoryStream
//     byte[] buffer = new byte[8192]; // Adjust buffer size as needed
//     MemoryStream memoryStream = new MemoryStream();
//     CancellationToken cancellationToken = CancellationToken.None;
// while (true)
// {
//       ReadResult readResult = await signalingChannel.ReadAsync(buffer.Length);

//     // Extract data from ReadOnlySequence<byte> (readResult.Data)
//     ReadOnlySequence<byte> data = readResult.Data;

//     // Determine how many bytes were read
//     int bytesRead = (int)data.Length;

//     if (bytesRead == 0)
//     {
//         break; // Connection closed
//     }

//     // Write the data from ReadOnlySequence<byte> into the MemoryStream
//     foreach (var segment in data)
//     {
//         await memoryStream.WriteAsync(segment);
//     }}

//    memoryStream.Position = 0; // Reset position for reading from the beginning
      Socket connectedSocket = context.Socket;// existing connected socket;
// connectedSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
// Create a new TcpClient and assign the existing socket to it
TcpClient tcpClient = new TcpClient
{
    Client = connectedSocket // Assign the connected socket to TcpClient
};

// Now you can use the TcpClient as usual
NetworkStream networkStream = tcpClient.GetStream();
        SslClientAuthenticationOptions clientAuthenticationOptions = new()
        {
            TargetHost = context.RemoteEndpoint.ToString(),
            ApplicationProtocols = _protocols,
            RemoteCertificateValidationCallback = (_, c, _, _) => VerifyRemoteCertificate(context.RemotePeer.Identity.PeerId.ToString(), c),
            ClientCertificates = new X509CertificateCollection { CertificateHelper.CertificateFromIdentity(_sessionKey, context.LocalPeer.Identity) },
        };
//  await signalingChannel.WriteLineAsync("/multistream/1.0.0\n/tls/1.0.0");
        SslStream sslStream = new(networkStream, false, clientAuthenticationOptions.RemoteCertificateValidationCallback);

        try
        {
            await sslStream.AuthenticateAsClientAsync(clientAuthenticationOptions);

            if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http2)
            {
                _logger?.LogDebug("HTTP/2 protocol negotiated");
            }
            else if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11)
            {
                _logger?.LogDebug("HTTP/1.1 protocol negotiated");
            }
            else if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http3)
            {
                _logger?.LogDebug("HTTP/3 protocol negotiated");
            }
            else
            {
                _logger?.LogDebug("Unknown protocol negotiated");
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError("An error occurred while authenticating the server: {Message}", ex.Message);
            return;
        }
        //  NetworkStream networkStream = tcpClient.GetStream();

        LastNegotiatedApplicationProtocol = sslStream.NegotiatedApplicationProtocol;

        IChannel upChannel = channelFactory.SubDial(context);
        await ProcessStreamsAsync(sslStream, tcpClient, upChannel, context);

        signalingChannel.GetAwaiter().OnCompleted(() =>
        {
            // tcpClient.Close();
        });
    }

    private static bool VerifyRemoteCertificate(string? remotePeerId, X509Certificate? certificate)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate), "Certificate cannot be null.");
        }

        return CertificateHelper.ValidateCertificate(certificate as X509Certificate2, remotePeerId);
    }

    private static Task ProcessStreamsAsync(SslStream sslStream, TcpClient tcpClient,  IChannel upChannel, IPeerContext context, CancellationToken cancellationToken = default)
    {
        upChannel.GetAwaiter().OnCompleted(() =>
        {
            sslStream.Close();
        });

        Task t = Task.Run(async () =>
        {
            byte[] buffer = new byte[4096];
            try
            {
                while (true)
                {
                    int bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    if (bytesRead == 0)
                        break;

                    if (await upChannel.WriteAsync(new ReadOnlySequence<byte>(buffer.AsMemory(0, bytesRead)), cancellationToken) != IOResult.Ok)
                        await upChannel.WriteEofAsync();
                }
            }
            catch (Exception)
            {
                await upChannel.CloseAsync();
            }
        }, cancellationToken);

        Task t2 = Task.Run(async () =>
        {
            try
            {
                await foreach (ReadOnlySequence<byte> data in upChannel.ReadAllAsync(cancellationToken))
                {
                    await sslStream.WriteAsync(data.ToArray(), cancellationToken);
                }
            }
            catch (Exception)
            {
                await upChannel.CloseAsync();
            }
        }, cancellationToken);

        sslStream.Dispose();
        tcpClient.Close();

        return Task.WhenAny(t, t2).ContinueWith(_ => { });
    }
}
