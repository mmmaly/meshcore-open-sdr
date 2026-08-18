// meshcore-sdr-node: a MeshCore companion node whose radio is a pair of
// SDRs - an RTL-SDR receiving through lora_rx, a HackRF transmitting
// through lora_tx. The meshcore-open app connects over TCP.
#include <cstdio>
#include <cstring>
#include <csignal>
#include <ctime>
#include <thread>
#include <unistd.h>

#include "node_config.h"
#include "radio_sdr.h"
#include "node.h"
#include "companion_server.h"

static CompanionServer* g_server = nullptr;
static void on_signal(int) {
    if (g_server) g_server->stop();
    _exit(0);
}

int main(int argc, char* argv[]) {
    const char* cfg_path = "sdr-node.conf";
    bool advertise = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) cfg_path = argv[++i];
        else if (strcmp(argv[i], "-a") == 0) advertise = true;
        else {
            fprintf(stderr, "Usage: %s [-c config] [-a]\n"
                            "  -c <file>  config file (default sdr-node.conf)\n"
                            "  -a         send a flood self-advert on startup\n",
                    argv[0]);
            return 1;
        }
    }

    std::string err;
    NodeConfig cfg = NodeConfig::load(cfg_path, err);
    if (!err.empty()) { fprintf(stderr, "%s\n", err.c_str()); return 1; }

    auto id = NodeIdentity::loadOrCreate(cfg.identity_file, err);
    if (!id) { fprintf(stderr, "identity: %s\n", err.c_str()); return 1; }

    RadioConfig rc;
    rc.rx_binary = cfg.rx_binary;
    rc.tx_binary = cfg.tx_binary;
    rc.rx_device = cfg.rx_device;
    rc.rx_channels = cfg.rx_channels;
    rc.rx_sfs = cfg.rx_sfs;
    rc.bw = cfg.bw;
    rc.rx_ppm = cfg.rx_ppm;
    rc.tx_freq = cfg.tx_freq;
    rc.tx_sf = cfg.tx_sf;
    rc.tx_cr = cfg.tx_cr;
    rc.tx_ppm = cfg.tx_ppm;
    rc.tx_vga = cfg.tx_vga;
    rc.tx_amp = cfg.tx_amp;
    rc.tx_duty = cfg.tx_duty;

    SdrRadio radio(rc);
    Node node(cfg, *id, radio);

    if (!radio.start([&node](const RxPacket& p) { node.onRxPacket(p); })) {
        fprintf(stderr, "failed to start lora_rx\n");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (advertise) {
        std::thread([&node] {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            node.sendSelfAdvert(true);
        }).detach();
    }

    CompanionServer server(node, cfg.port);
    g_server = &server;
    server.run();
    return 0;
}
