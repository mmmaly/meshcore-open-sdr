// Daemon configuration and node identity.
//
// Config is a plain key=value file; the identity is an orlp-format Ed25519
// private key (32-byte seed + 32-byte public key, hex) in its own file next
// to the config, created on first run with mode 600. Channel keys are hex
// lines in a separate file that is never printed and never committed.
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

struct ChannelDef {
    std::string name;      // display name, e.g. "Public"
    std::string keyHex;    // 16-byte AES key, lowercase hex
};

struct NodeConfig {
    // Node
    std::string name = "SDR Node";
    std::string identity_file = "identity.key";
    std::string channels_file = "channels.txt";
    std::optional<double> lat, lon;

    // TCP server
    int port = 5000;

    // Radio (mirrors RadioConfig; parsed into it by main)
    std::string rx_binary = "lora_rx";
    std::string tx_binary = "lora_tx";
    std::string rx_device;
    std::string rx_channels = "869618000";
    std::string rx_sfs = "7,8";
    uint32_t bw = 62500;
    int rx_ppm = 0;
    uint32_t tx_freq = 869618000;
    int tx_sf = 7;
    int tx_cr = 1;
    int tx_ppm = 0;
    int tx_vga = 30;
    double tx_duty = 10.0;

    static NodeConfig load(const std::string& path, std::string& err);
};

struct NodeIdentity {
    std::string privateKeyHex;  // 128 hex chars, orlp format (seed + pub)
    std::string publicKeyHex;   // 64 hex chars

    // Load from file, or generate + persist (mode 600) when absent.
    static std::optional<NodeIdentity> loadOrCreate(const std::string& path,
                                                    std::string& err);
};

// channels.txt: one "name,keyhex" per line ('#' comments). The app can add
// channels at runtime; setChannel persists back to the same file.
std::vector<ChannelDef> loadChannels(const std::string& path);
bool saveChannels(const std::string& path, const std::vector<ChannelDef>& channels);
