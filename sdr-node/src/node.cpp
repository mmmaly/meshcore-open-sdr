#include "node.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>

#include "meshcore/meshcore.h"

using namespace meshcore;

static void putU32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
    v.push_back((x >> 16) & 0xFF);
    v.push_back((x >> 24) & 0xFF);
}

static uint32_t getU32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

Node::Node(const NodeConfig& cfg, const NodeIdentity& id, SdrRadio& radio)
    : cfg_(cfg), id_(id), radio_(radio) {
    channels_ = loadChannels(cfg_.channels_file);
    fprintf(stderr, "[node] %s, pubkey %.16s..., %zu channel(s)\n",
            cfg_.name.c_str(), id_.publicKeyHex.c_str(), channels_.size());
    txThread_ = std::thread(&Node::txWorker, this);
}

Node::~Node() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        txStop_ = true;
    }
    txCv_.notify_all();
    if (txThread_.joinable()) txThread_.join();
}

void Node::enqueueTx(std::string hex) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        txQueue_.push_back(std::move(hex));
    }
    txCv_.notify_one();
}

void Node::txWorker() {
    std::unique_lock<std::mutex> lk(mtx_);
    while (true) {
        txCv_.wait(lk, [this] { return txStop_ || !txQueue_.empty(); });
        if (txStop_) return;
        std::string hex = std::move(txQueue_.front());
        txQueue_.pop_front();
        lk.unlock();
        if (!radio_.transmit(hex))
            fprintf(stderr, "[node] tx failed for a queued packet\n");
        lk.lock();
    }
}

void Node::setAppSender(AppSender sender) {
    std::lock_guard<std::mutex> lk(mtx_);
    appSender_ = std::move(sender);
}

// SELF_INFO: [5][advtype][txpwr][maxtxpwr][pubkey32][lat4][lon4][multiacks]
//            [locpolicy][telemetry][manualadd][freq4][bw4][sf][cr][name\0]
std::vector<uint8_t> Node::buildSelfInfo() {
    std::vector<uint8_t> f{RESP_SELF_INFO, 1 /*chat*/, 14 /*dBm-ish*/, 14};
    auto pk = hexToBytes(id_.publicKeyHex);
    f.insert(f.end(), pk.begin(), pk.end());
    putU32(f, (uint32_t)(int32_t)((cfg_.lat ? *cfg_.lat : 0.0) * 1e6));
    putU32(f, (uint32_t)(int32_t)((cfg_.lon ? *cfg_.lon : 0.0) * 1e6));
    f.push_back(0);   // multi_acks
    f.push_back(0);   // advert_loc_policy
    f.push_back(0);   // telemetry modes
    f.push_back(1);   // manual-add byte: 1 => app treats auto-add as enabled
    putU32(f, cfg_.tx_freq);
    putU32(f, cfg_.bw);
    f.push_back((uint8_t)cfg_.tx_sf);
    f.push_back((uint8_t)cfg_.tx_cr);
    f.insert(f.end(), cfg_.name.begin(), cfg_.name.end());
    f.push_back(0);
    return f;
}

// DEVICE_INFO: [13][fw_ver][max_contacts/2][max_channels][16 reserved]
//              [manufacturer 40][fw version 20][client_repeat]
std::vector<uint8_t> Node::buildDeviceInfo() {
    std::vector<uint8_t> f(82, 0);
    f[0] = RESP_DEVICE_INFO;
    f[1] = 7;                       // firmware ver code: pre-stats featureset
    f[2] = 100;                     // -> 200 max contacts
    f[3] = MAX_CHANNELS;
    strncpy((char*)f.data() + 8, __DATE__, 11);
    const char* manu = "MeshCore SDR (RTL-SDR rx, HackRF tx)";
    strncpy((char*)f.data() + 20, manu, 39);
    strncpy((char*)f.data() + 60, "sdr-node 0.1", 19);
    f[81] = 0;                      // client_repeat
    return f;
}

// Contact frame (148 bytes): [code][pubkey32][type][flags][pathlen][path64]
//                            [name32][last_advert4][lat4][lon4][lastmod4]
std::vector<uint8_t> Node::buildContactFrame(const Contact& c, uint8_t code) {
    std::vector<uint8_t> f;
    f.reserve(148);
    f.push_back(code);
    f.insert(f.end(), c.pubKey.begin(), c.pubKey.end());
    f.push_back(c.type);
    f.push_back(0);                 // flags
    f.push_back(0xFF);              // path: unknown/flood
    f.insert(f.end(), 64, 0);
    char name[32] = {0};
    strncpy(name, c.name.c_str(), 31);
    f.insert(f.end(), name, name + 32);
    putU32(f, c.lastAdvert);
    putU32(f, (uint32_t)c.lat);
    putU32(f, (uint32_t)c.lon);
    putU32(f, c.lastMod);
    return f;
}

void Node::handleCommand(const std::vector<uint8_t>& f, const AppSender& send) {
    if (f.empty()) return;
    switch (f[0]) {
    case CMD_DEVICE_QUERY:
        send(buildDeviceInfo());
        break;
    case CMD_APP_START:
        send(buildSelfInfo());
        break;
    case CMD_GET_CUSTOM_VAR: {
        std::vector<uint8_t> r{RESP_CUSTOM_VARS};
        const char* vars = "gps:0";
        r.insert(r.end(), vars, vars + strlen(vars));
        r.push_back(0);
        send(r);
        break;
    }
    case CMD_GET_BATT_AND_STORAGE: {
        // Mains powered: report a healthy fake cell so the UI shows full
        std::vector<uint8_t> r{RESP_BATT_AND_STORAGE};
        r.push_back(4200 & 0xFF); r.push_back(4200 >> 8);
        putU32(r, 0); putU32(r, 0);
        send(r);
        break;
    }
    case CMD_GET_AUTO_ADD_CONFIG: {
        // overwriteOldest | chat | repeater | room | sensor
        send({RESP_AUTO_ADD_CONFIG, 0x1F});
        break;
    }
    case CMD_SET_AUTO_ADD_CONFIG:
    case CMD_SET_DEVICE_TIME:      // host clock is NTP-disciplined; ignore
    case CMD_SET_OTHER_PARAMS:
        send({RESP_OK});           // firmware OKs every setter
        break;
    case CMD_SET_ADVERT_NAME:
        if (f.size() > 1) {
            // The official app NUL-terminates the name in the frame
            // (meshcore-open does not). A kept NUL ends up inside the
            // "name: text" plaintext on air, and every receiver truncates
            // the message at it - showing an empty message.
            std::string name((const char*)f.data() + 1, f.size() - 1);
            auto nul = name.find('\0');
            if (nul != std::string::npos) name.resize(nul);
            if (!name.empty()) {
                std::lock_guard<std::mutex> lk(mtx_);
                cfg_.name = name;
                fprintf(stderr, "[node] name set to '%s'\n", cfg_.name.c_str());
            }
        }
        send({RESP_OK});
        break;
    case CMD_SET_ADVERT_LATLON:
        if (f.size() >= 9) {
            std::lock_guard<std::mutex> lk(mtx_);
            cfg_.lat = (int32_t)getU32(f.data() + 1) / 1e6;
            cfg_.lon = (int32_t)getU32(f.data() + 5) / 1e6;
        }
        send({RESP_OK});
        break;
    case CMD_SET_RADIO_PARAMS:
        if (f.size() >= 11) {
            std::lock_guard<std::mutex> lk(mtx_);
            RadioConfig& rc = radio_.config();
            rc.tx_freq = getU32(f.data() + 1);
            rc.bw = getU32(f.data() + 5);
            rc.tx_sf = f[9];
            rc.tx_cr = f[10] >= 5 ? f[10] - 4 : f[10];
            cfg_.tx_freq = rc.tx_freq; cfg_.bw = rc.bw;
            cfg_.tx_sf = rc.tx_sf; cfg_.tx_cr = rc.tx_cr;
            fprintf(stderr, "[node] radio params: %u Hz bw %u sf %d cr %d "
                    "(applied to TX; restart daemon to retune RX)\n",
                    rc.tx_freq, rc.bw, rc.tx_sf, rc.tx_cr);
        }
        send({RESP_OK});
        break;
    case CMD_SET_RADIO_TX_POWER:
        send({RESP_OK});           // HackRF gain is configured host-side
        break;
    case CMD_SET_FLOOD_SCOPE:
        send({RESP_OK});           // scoping not implemented; ack so sends proceed
        break;
    case CMD_GET_CHANNEL: {
        uint8_t idx = f.size() > 1 ? f[1] : 0;
        if (idx >= MAX_CHANNELS) {
            // Real firmware errors past MAX_GROUP_CHANNELS; the official
            // app scans until it sees this, so answering every index with
            // a valid empty slot makes its channel count run away
            send({RESP_ERR, 2 /*not found*/});
            break;
        }
        std::vector<uint8_t> r(50, 0);
        r[0] = RESP_CHANNEL_INFO;
        r[1] = idx;
        std::lock_guard<std::mutex> lk(mtx_);
        if (idx < channels_.size()) {
            strncpy((char*)r.data() + 2, channels_[idx].name.c_str(), 31);
            auto key = hexToBytes(channels_[idx].keyHex);
            if (key.size() == 16) memcpy(r.data() + 34, key.data(), 16);
        }
        send(r);                   // empty name = free slot, still must reply
        break;
    }
    case CMD_SET_CHANNEL:
        if (f.size() >= 50 && f[1] < MAX_CHANNELS) {
            uint8_t idx = f[1];
            char name[33] = {0};
            memcpy(name, f.data() + 2, 32);
            std::lock_guard<std::mutex> lk(mtx_);
            if (channels_.size() <= idx) channels_.resize(idx + 1);
            channels_[idx].name = name;
            channels_[idx].keyHex = toLower(bytesToHex(f.data() + 34, 16));
            if (channels_[idx].name.empty())
                channels_[idx].keyHex.clear();   // deleted slot
            saveChannels(cfg_.channels_file, channels_);
            fprintf(stderr, "[node] channel %u set: '%s'\n", idx, name);
            send({RESP_OK});
        } else {
            send({RESP_ERR, (uint8_t)(f.size() >= 2 && f[1] >= MAX_CHANNELS
                                      ? 2 /*not found*/ : 6 /*illegal arg*/)});
        }
        break;
    case CMD_SYNC_NEXT_MESSAGE: {
        std::lock_guard<std::mutex> lk(mtx_);
        if (inbox_.empty()) {
            send({RESP_NO_MORE_MESSAGES});
        } else {
            send(inbox_.front().frame);
            inbox_.pop_front();
        }
        break;
    }
    case CMD_GET_CONTACTS: {
        uint32_t since = f.size() >= 5 ? getU32(f.data() + 1) : 0;
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<uint8_t> start{RESP_CONTACTS_START};
        putU32(start, (uint32_t)contacts_.size());
        send(start);
        for (const auto& [k, c] : contacts_)
            if (c.lastMod > since)
                send(buildContactFrame(c, RESP_CONTACT));
        send({RESP_END_OF_CONTACTS});
        break;
    }
    case CMD_REMOVE_CONTACT:
        if (f.size() >= 33) {
            std::lock_guard<std::mutex> lk(mtx_);
            contacts_.erase(toLower(bytesToHex(f.data() + 1, 32)));
        }
        break;
    case CMD_SEND_SELF_ADVERT:
        sendSelfAdvert(f.size() > 1 && f[1] != 0);
        send({RESP_OK});
        break;
    case CMD_SEND_CHANNEL_TXT_MSG:
        handleSendChannelText(f, send);
        break;
    case CMD_SEND_TXT_MSG:
        // Direct messages need X25519 contact crypto - not in v1
        send({RESP_ERR, 1 /*unsupported*/});
        break;
    default:
        fprintf(stderr, "[node] unhandled cmd 0x%02X (%zu bytes)\n", f[0], f.size());
        send({RESP_ERR, 1});
        break;
    }
}

// [3][txt_type][channel_idx][timestamp4][text...]\0 -> encrypt, transmit,
// reply SENT. The app sends bare text; the node prefixes "name: " on air.
void Node::handleSendChannelText(const std::vector<uint8_t>& f, const AppSender& send) {
    if (f.size() < 8) { send({RESP_ERR, 4}); return; }
    uint8_t idx = f[2];
    std::string text((const char*)f.data() + 7, f.size() - 7);
    auto nul = text.find('\0');
    if (nul != std::string::npos) text.resize(nul);

    std::string keyHex, myName;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (idx >= channels_.size() || channels_[idx].keyHex.empty()) {
            send({RESP_ERR, 2 /*bad channel*/});
            return;
        }
        keyHex = channels_[idx].keyHex;
        myName = cfg_.name;
    }

    uint32_t now = (uint32_t)time(nullptr);
    auto payload = MeshCorePacketEncoder::buildGroupTextPayload(keyHex, myName, text, now, 0);
    if (!payload.success) { send({RESP_ERR, 4}); return; }
    auto pkt = MeshCorePacketEncoder::buildPacket(RouteType::Flood,
                                                  PayloadType::GroupText, payload.bytes);
    if (!pkt.success) { send({RESP_ERR, 4}); return; }

    std::string hex = toLower(bytesToHex(pkt.bytes));
    {
        // Our own RTL-SDR will hear this transmission; pre-mark it seen
        std::lock_guard<std::mutex> lk(mtx_);
        seen_[toLower(bytesToHex(payload.bytes))] = (double)now;
    }

    enqueueTx(hex);

    // SENT immediately, like firmware: the packet is queued for the radio.
    // [6][is_flood][ack_hash4 = 0: channel floods carry no ack][est_ms4]
    std::vector<uint8_t> r{RESP_SENT, 1};
    putU32(r, 0);
    putU32(r, 5000);
    send(r);
    fprintf(stderr, "[node] channel %u tx queued: %zu chars\n", idx, text.size());
}

void Node::sendSelfAdvert(bool flood) {
    std::string myName;
    std::optional<std::pair<double, double>> latLon;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        myName = cfg_.name;
        if (cfg_.lat && cfg_.lon) latLon = std::make_pair(*cfg_.lat, *cfg_.lon);
    }
    auto payload = MeshCorePacketEncoder::buildAdvertPayload(
        id_.privateKeyHex, id_.publicKeyHex, (uint32_t)time(nullptr),
        myName, DeviceRole::ChatNode, latLon);
    if (!payload.success) {
        fprintf(stderr, "[node] advert build failed: %s\n", payload.error.c_str());
        return;
    }
    auto pkt = MeshCorePacketEncoder::buildPacket(
        flood ? RouteType::Flood : RouteType::Direct,
        PayloadType::Advert, payload.bytes);
    if (!pkt.success) return;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        seen_[toLower(bytesToHex(payload.bytes))] = (double)time(nullptr);
    }
    enqueueTx(toLower(bytesToHex(pkt.bytes)));
    fprintf(stderr, "[node] self advert queued (%s)\n", flood ? "flood" : "zero-hop");
}

bool Node::seenBefore(const std::string& payloadHex, double now) {
    // Flood rebroadcasts repeat the same payload with different paths, and
    // our own transmissions come right back through the RTL-SDR: dedup on
    // the payload, not the whole packet.
    auto it = seen_.find(payloadHex);
    if (it != seen_.end() && now - it->second < 600.0) return true;
    seen_[payloadHex] = now;
    if (seen_.size() > 4096) {
        for (auto i = seen_.begin(); i != seen_.end();)
            i = (now - i->second > 600.0) ? seen_.erase(i) : std::next(i);
    }
    return false;
}

void Node::queueForApp(std::vector<uint8_t> frame) {
    AppSender sender;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        inbox_.push_back({std::move(frame)});
        while (inbox_.size() > 256) inbox_.pop_front();
        sender = appSender_;
    }
    if (sender) sender({PUSH_MSG_WAITING});
}

void Node::onRxPacket(const RxPacket& pkt) {
    lastSnr_ = pkt.snr;
    auto decoded = MeshCorePacketDecoder::decode(pkt.hex);
    if (!decoded.isValid && decoded.payloadRaw.empty()) return;

    std::string payloadHex = toLower(decoded.payloadRaw);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (seenBefore(payloadHex, pkt.time)) {
            // Own transmissions coming back through the RTL-SDR land here
            // too - useful as on-air confirmation in the log
            fprintf(stderr, "[node] heard duplicate/own payload (snr %.1f)\n", pkt.snr);
            return;
        }
    }

    if (decoded.payloadType == PayloadType::GroupText) {
        // Which of our channels does the hash byte match?
        auto payload = hexToBytes(decoded.payloadRaw);
        if (payload.size() < 4) return;
        std::string hashHex = toLower(bytesToHex(payload.data(), 1));

        int idx = -1;
        std::string keyHex;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            for (size_t i = 0; i < channels_.size(); i++) {
                if (channels_[i].keyHex.empty()) continue;
                if (toLower(ChannelCrypto::calculateChannelHash(channels_[i].keyHex)) == hashHex) {
                    idx = (int)i;
                    keyHex = channels_[i].keyHex;
                    break;
                }
            }
        }
        if (idx < 0) return;   // not one of ours

        auto res = ChannelCrypto::decryptGroupTextMessage(
            bytesToHex(payload.data() + 3, payload.size() - 3),
            bytesToHex(payload.data() + 1, 2), keyHex);
        if (!res.success) return;

        // RESP_CHANNEL_MSG_RECV: [8][ch][pathlen i8][txt_type=0][ts4]["name: text"\0]
        std::vector<uint8_t> f{RESP_CHANNEL_MSG_RECV, (uint8_t)idx,
                               decoded.pathLength, 0};
        putU32(f, res.timestamp);
        std::string line = res.sender ? (*res.sender + ": " + res.message) : res.message;
        f.insert(f.end(), line.begin(), line.end());
        f.push_back(0);
        if (f.size() > 172) f.resize(172);
        queueForApp(std::move(f));
        fprintf(stderr, "[node] rx channel %d msg from %s (snr %.1f)\n",
                idx, res.sender ? res.sender->c_str() : "?", pkt.snr);
    } else if (decoded.payloadType == PayloadType::Advert) {
        auto adv = MeshCorePacketDecoder::decodeWithVerification(pkt.hex);
        if (!adv.payloadDecoded) return;
        auto* a = std::get_if<AdvertPayload>(&*adv.payloadDecoded);
        if (!a || !a->signatureValid.value_or(false)) return;
        if (toLower(a->publicKey) == toLower(id_.publicKeyHex)) return;

        Contact c;
        c.pubKey = hexToBytes(a->publicKey);
        c.type = (uint8_t)a->appData.deviceRole;
        c.name = a->appData.name.value_or(a->publicKey.substr(0, 8));
        c.lastAdvert = a->timestamp;
        c.lastMod = (uint32_t)time(nullptr);
        if (a->appData.latitude) c.lat = (int32_t)(*a->appData.latitude * 1e6);
        if (a->appData.longitude) c.lon = (int32_t)(*a->appData.longitude * 1e6);

        AppSender sender;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            contacts_[toLower(a->publicKey)] = c;
            sender = appSender_;
        }
        if (sender) sender(buildContactFrame(c, PUSH_NEW_ADVERT));
        fprintf(stderr, "[node] advert: %s (%s, snr %.1f)\n", c.name.c_str(),
                a->publicKey.substr(0, 12).c_str(), pkt.snr);
    }
    // Other payload types (acks, paths, traces, direct messages) are not for
    // a v1 channel-chat node; they are heard and ignored.
}
