// Emits test mesh packets (hex) for the fake-radio protocol test:
// a GroupText on the well-known public channel and a signed advert.
#include <cstdio>
#include "meshcore/meshcore.h"

using namespace meshcore;

int main() {
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
    return 0;
}
