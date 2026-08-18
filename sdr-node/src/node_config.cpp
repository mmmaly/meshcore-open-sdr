#include "node_config.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <openssl/rand.h>

#include "meshcore/crypto/ed25519.h"
#include "meshcore/utils/hex.h"

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

NodeConfig NodeConfig::load(const std::string& path, std::string& err) {
    NodeConfig c;
    std::ifstream f(path);
    if (!f) {
        err = "cannot open config " + path;
        return c;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
        if (k == "name") c.name = v;
        else if (k == "identity_file") c.identity_file = v;
        else if (k == "channels_file") c.channels_file = v;
        else if (k == "lat") c.lat = atof(v.c_str());
        else if (k == "lon") c.lon = atof(v.c_str());
        else if (k == "port") c.port = atoi(v.c_str());
        else if (k == "rx_binary") c.rx_binary = v;
        else if (k == "tx_binary") c.tx_binary = v;
        else if (k == "rx_device") c.rx_device = v;
        else if (k == "rx_channels") c.rx_channels = v;
        else if (k == "rx_sfs") c.rx_sfs = v;
        else if (k == "bw") c.bw = (uint32_t)atol(v.c_str());
        else if (k == "rx_ppm") c.rx_ppm = atoi(v.c_str());
        else if (k == "tx_freq") c.tx_freq = (uint32_t)atol(v.c_str());
        else if (k == "tx_sf") c.tx_sf = atoi(v.c_str());
        else if (k == "tx_cr") c.tx_cr = atoi(v.c_str());
        else if (k == "tx_ppm") c.tx_ppm = atoi(v.c_str());
        else if (k == "tx_vga") c.tx_vga = atoi(v.c_str());
        else if (k == "tx_amp") c.tx_amp = atoi(v.c_str()) != 0;
        else if (k == "tx_duty") c.tx_duty = atof(v.c_str());
        else fprintf(stderr, "[config] unknown key '%s'\n", k.c_str());
    }
    return c;
}

std::optional<NodeIdentity> NodeIdentity::loadOrCreate(const std::string& path,
                                                       std::string& err) {
    std::ifstream f(path);
    if (f) {
        std::string hex;
        f >> hex;
        if (hex.size() != 128) {
            err = "identity file must hold a 128-hex-char orlp private key";
            return std::nullopt;
        }
        NodeIdentity id;
        id.privateKeyHex = hex;
        try {
            id.publicKeyHex = meshcore::Ed25519::derivePublicKey(hex);
        } catch (const std::exception& e) {
            err = e.what();
            return std::nullopt;
        }
        return id;
    }

    // First run: fresh identity. orlp format is seed(32) + public(32).
    uint8_t seed[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        err = "RAND_bytes failed";
        return std::nullopt;
    }
    std::string seedHex = meshcore::bytesToHex(seed, 32);
    NodeIdentity id;
    try {
        id.publicKeyHex = meshcore::Ed25519::derivePublicKey(seedHex + seedHex);
    } catch (const std::exception& e) {
        err = e.what();
        return std::nullopt;
    }
    id.privateKeyHex = seedHex + id.publicKeyHex;

    FILE* out = fopen(path.c_str(), "w");
    if (!out) {
        err = "cannot write identity file " + path;
        return std::nullopt;
    }
    chmod(path.c_str(), 0600);
    fprintf(out, "%s\n", id.privateKeyHex.c_str());
    fclose(out);
    fprintf(stderr, "[identity] new node identity created in %s\n", path.c_str());
    return id;
}

std::vector<ChannelDef> loadChannels(const std::string& path) {
    std::vector<ChannelDef> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto comma = line.find(',');
        if (comma == std::string::npos) continue;
        ChannelDef ch;
        ch.name = trim(line.substr(0, comma));
        ch.keyHex = trim(line.substr(comma + 1));
        // A channel secret is 16 bytes. Longer hex here is usually a pasted
        // node identity key - refusing it now beats a cryptic send error later.
        if (!ch.name.empty() &&
            (ch.keyHex.size() != 32 ||
             ch.keyHex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)) {
            fprintf(stderr, "[config] channel '%s': key is not 32 hex chars, skipping\n",
                    ch.name.c_str());
            continue;
        }
        out.push_back(ch);
    }
    return out;
}

bool saveChannels(const std::string& path, const std::vector<ChannelDef>& channels) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    chmod(path.c_str(), 0600);
    fprintf(f, "# name,keyhex - one channel per line, index = line order\n");
    for (const auto& ch : channels)
        fprintf(f, "%s,%s\n", ch.name.c_str(), ch.keyHex.c_str());
    fclose(f);
    return true;
}
