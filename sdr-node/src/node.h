// The MeshCore node: protocol dispatch and mesh logic.
//
// Speaks the companion-radio protocol frames (content only; TCP framing is
// CompanionServer's job) on one side, and raw mesh packets through SdrRadio
// on the other. Byte layouts follow the meshcore-open connector
// implementation (lib/connector/meshcore_connector.dart), which is the
// authoritative peer here.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "node_config.h"
#include "radio_sdr.h"

// Companion protocol constants (meshcore_protocol.dart)
enum Cmd : uint8_t {
    CMD_APP_START = 1,
    CMD_SEND_TXT_MSG = 2,
    CMD_SEND_CHANNEL_TXT_MSG = 3,
    CMD_GET_CONTACTS = 4,
    CMD_SET_DEVICE_TIME = 6,
    CMD_SEND_SELF_ADVERT = 7,
    CMD_SET_ADVERT_NAME = 8,
    CMD_SYNC_NEXT_MESSAGE = 10,
    CMD_SET_RADIO_PARAMS = 11,
    CMD_SET_RADIO_TX_POWER = 12,
    CMD_SET_ADVERT_LATLON = 14,
    CMD_REMOVE_CONTACT = 15,
    CMD_GET_BATT_AND_STORAGE = 20,
    CMD_DEVICE_QUERY = 22,
    CMD_GET_CHANNEL = 31,
    CMD_SET_CHANNEL = 32,
    CMD_SET_OTHER_PARAMS = 38,
    CMD_GET_CUSTOM_VAR = 40,
    CMD_SET_FLOOD_SCOPE = 54,
    CMD_GET_STATS = 56,
    CMD_SET_AUTO_ADD_CONFIG = 58,
    CMD_GET_AUTO_ADD_CONFIG = 59,
};

enum Resp : uint8_t {
    RESP_OK = 0,
    RESP_ERR = 1,
    RESP_CONTACTS_START = 2,
    RESP_CONTACT = 3,
    RESP_END_OF_CONTACTS = 4,
    RESP_SELF_INFO = 5,
    RESP_SENT = 6,
    RESP_CONTACT_MSG_RECV = 7,
    RESP_CHANNEL_MSG_RECV = 8,
    RESP_NO_MORE_MESSAGES = 10,
    RESP_BATT_AND_STORAGE = 12,
    RESP_DEVICE_INFO = 13,
    RESP_CHANNEL_INFO = 18,
    RESP_CUSTOM_VARS = 21,
    RESP_AUTO_ADD_CONFIG = 25,
};

enum Push : uint8_t {
    PUSH_ADVERT = 0x80,
    PUSH_MSG_WAITING = 0x83,
    PUSH_NEW_ADVERT = 0x8A,
};

struct Contact {
    std::vector<uint8_t> pubKey;   // 32
    uint8_t type = 1;              // 1=chat 2=repeater 3=room 4=sensor
    std::string name;
    uint32_t lastAdvert = 0;
    uint32_t lastMod = 0;
    int32_t lat = 0, lon = 0;      // x1e6, 0 = unknown
};

// A frame waiting for the app's CMD_SYNC_NEXT_MESSAGE pull
struct QueuedMessage {
    std::vector<uint8_t> frame;    // ready-to-send RESP_CHANNEL_MSG_RECV frame
};

class Node {
public:
    // Mirrors firmware MAX_GROUP_CHANNELS: DEVICE_INFO advertises it and
    // GET/SET_CHANNEL error past it (the official app scans until that error)
    static constexpr uint8_t MAX_CHANNELS = 8;

    // sendToApp delivers one protocol frame to the connected app (no-op when
    // disconnected); it must be safe to call from the radio thread.
    using AppSender = std::function<void(const std::vector<uint8_t>&)>;

    Node(const NodeConfig& cfg, const NodeIdentity& id, SdrRadio& radio);

    // One command frame from the app -> zero or more response frames, sent
    // in order through `send`. Called from the server thread.
    void handleCommand(const std::vector<uint8_t>& frame, const AppSender& send);

    // One CRC-valid packet from the radio. Called from the radio thread.
    void onRxPacket(const RxPacket& pkt);

    // Push channel for async node->app frames; server sets/clears it.
    void setAppSender(AppSender sender);

    void sendSelfAdvert(bool flood);

private:
    std::vector<uint8_t> buildSelfInfo();
    std::vector<uint8_t> buildDeviceInfo();
    std::vector<uint8_t> buildContactFrame(const Contact& c, uint8_t code);
    void handleSendChannelText(const std::vector<uint8_t>& f, const AppSender& send);
    void queueForApp(std::vector<uint8_t> frame);
    bool seenBefore(const std::string& payloadHex, double now);

    NodeConfig cfg_;
    NodeIdentity id_;
    SdrRadio& radio_;

    std::mutex mtx_;
    std::vector<ChannelDef> channels_;
    std::map<std::string, Contact> contacts_;       // key: pubkey hex
    std::deque<QueuedMessage> inbox_;
    std::map<std::string, double> seen_;            // payload hash -> time
    AppSender appSender_;
    float lastSnr_ = 0.0f;
};
