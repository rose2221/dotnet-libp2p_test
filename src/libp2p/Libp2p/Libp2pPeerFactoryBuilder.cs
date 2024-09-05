// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using Nethermind.Libp2p.Core;
using Nethermind.Libp2p.Protocols;
using Nethermind.Libp2p.Protocols.Pubsub;
using System.Runtime.Versioning;
using System.Net.Security;


namespace Nethermind.Libp2p.Stack;

[RequiresPreviewFeatures]
public class Libp2pPeerFactoryBuilder : PeerFactoryBuilderBase<Libp2pPeerFactoryBuilder, Libp2pPeerFactory>,
    ILibp2pPeerFactoryBuilder
{
    private bool enforcePlaintext;

    public ILibp2pPeerFactoryBuilder WithPlaintextEnforced()
    {
        enforcePlaintext = true;
        return this;
    }

    public Libp2pPeerFactoryBuilder(IServiceProvider? serviceProvider = default) : base(serviceProvider)
    {
    }

    protected override ProtocolStack BuildStack()
    {
        var protocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11, SslApplicationProtocol.Http2 , new SslApplicationProtocol("/yamux/1.0.0")    };

        ProtocolStack tcpEncryptionStack = enforcePlaintext ?
            Over<PlainTextProtocol>() :
            Over(new TlsProtocol(protocols));

        ProtocolStack tcpStack =
            Over<IpTcpProtocol>()
            .Over<MultistreamProtocol>()
            .Over(tcpEncryptionStack)
            .Over<MultistreamProtocol>()
            .Over<YamuxProtocol>();

        return
            Over<MultiaddressBasedSelectorProtocol>()
            .Over<QuicProtocol>().Or(tcpStack)
            .Over<MultistreamProtocol>()
            .AddAppLayerProtocol<IdentifyProtocol>()
            //.AddAppLayerProtocol<GossipsubProtocolV12>()
            //.AddAppLayerProtocol<GossipsubProtocolV11>()
            .AddAppLayerProtocol<GossipsubProtocol>()
            .AddAppLayerProtocol<FloodsubProtocol>();
    }
}
