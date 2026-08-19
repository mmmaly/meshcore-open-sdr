// Emits test mesh packets (hex) for the fake-radio protocol test:
// a GroupText on the well-known public channel, a signed advert, and -
// when the node public key is passed as argv[1] - a direct message from a
// fixed test peer to that node.
#include <cstdio>
#include "meshcore/meshcore.h"
#include "meshcore/crypto/peer_crypto.h"

using namespace meshcore;

int main(int argc, char* argv[]) {
    const std::string pubChannel = "8b3387e9c5cdea6ac9e5edbaa115cd72";

    auto gt = MeshCorePacketEncoder::buildGroupTextPayload(
        pubChannel, "TestPeer", "hello from the fake mesh", 1787090000u, 0);
    auto gtPkt = MeshCorePacketEncoder::buildPacket(
        RouteType::Flood, PayloadType::GroupText, gt.bytes);
    printf("GROUPTEXT %s\n", bytesToHex(gtPkt.bytes).c_str());

    std::string seed = "1111111111111111111111111111111111111111111111111111111111111111";
    std::string pub = Ed25519::derivePublicKey(seed + seed);
    std::string priv = seed + pub;
    auto adv = MeshCorePacketEncoder::buildAdvertPayload(
        priv, pub, 1787090001u, "FakeNode", DeviceRole::ChatNode,
        std::make_pair(48.15, 17.11));
    auto advPkt = MeshCorePacketEncoder::buildPacket(
        RouteType::Flood, PayloadType::Advert, adv.bytes);
    printf("ADVERT %s\n", bytesToHex(advPkt.bytes).c_str());

    if (argc > 1) {
        std::string nodePub = argv[1];
        std::string peerSeed = "3333333333333333333333333333333333333333333333333333333333333333";
        std::string peerPub = Ed25519::derivePublicKey(peerSeed + peerSeed);
        printf("PEERPUB %s\n", peerPub.c_str());

        std::string secret = PeerCrypto::keyExchange(peerSeed + peerSeed, nodePub);
        auto nodePubBytes = hexToBytes(nodePub);
        auto peerPubBytes = hexToBytes(peerPub);
        auto dm = PeerCrypto::buildTextMessagePayload(
            secret, nodePubBytes[0], peerPubBytes[0], 1787090100u, 0,
            "sukromny pozdrav");
        auto dmPkt = MeshCorePacketEncoder::buildPacket(
            RouteType::Flood, PayloadType::TextMessage, dm);
        printf("DM %s\n", bytesToHex(dmPkt.bytes).c_str());
        // ACK the peer would compute for a message the NODE sends it is
        // derived at runtime; the test reads it from RESP_SENT instead.
    }
    return 0;
}
