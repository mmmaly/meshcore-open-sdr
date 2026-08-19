// SDR radio backend for the MeshCore node daemon.
//
// Receive: owns a lora_rx child process (RTL-SDR) and parses its stable
// stdout contract — "rx cfg: freq=... sf=... bw=... snr=... cfo=... time=..."
// followed by "rx ok: <hex>" for each CRC-valid frame.
// Transmit: runs lora_tx (HackRF) per packet. Two physical radios, so
// receiving continues while transmitting.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <sys/types.h>

struct RxPacket {
    std::string hex;      // raw packet bytes as lowercase hex
    uint32_t freq = 0;    // channel frequency of the decoder that heard it
    int sf = 0;
    uint32_t bw = 0;
    float snr = 0.0f;
    float cfo = 0.0f;
    double time = 0.0;    // epoch seconds from the receiver
};

struct RadioConfig {
    // Receive side (RTL-SDR)
    std::string rx_binary = "lora_rx";
    std::string rx_device;              // -d selector; empty = device 0
    std::string rx_channels;            // -C list, e.g. "869432000,869618000"
    std::string rx_sfs;                 // -S list, e.g. "7,8"
    uint32_t bw = 62500;
    int rx_ppm = 0;
    bool rx_agc = true;                 // -G -T

    // Transmit side (HackRF)
    std::string tx_binary = "lora_tx";
    uint32_t tx_freq = 869618000;
    int tx_sf = 8;
    int tx_cr = 1;
    int tx_ppm = 0;
    int tx_vga = 30;
    bool tx_amp = false;                // HackRF PA (+11 dB); fine for TX,
                                        // it is the RX side the amp overloads
    double tx_duty = 10.0;              // EU 869.4-869.65 sub-band allows 10%
};

class SdrRadio {
public:
    using PacketHandler = std::function<void(const RxPacket&)>;

    explicit SdrRadio(const RadioConfig& cfg) : cfg_(cfg) {}
    ~SdrRadio() { stop(); }

    // Spawn lora_rx and start the reader thread; handler runs on that thread.
    bool start(PacketHandler handler);
    void stop();

    // Blocking transmit of one raw packet (hex). Runs lora_tx to completion;
    // returns false if the child failed. Estimated airtime is reported so the
    // caller can honor MeshCore timing if it wants.
    bool transmit(const std::string& hex);

    bool rxRunning() const { return rx_pid_ > 0 && running_; }
    uint64_t rxCount() const { return rx_count_; }
    uint64_t txCount() const { return tx_count_; }
    double lastRxTime() const { return last_rx_time_; }

    // Applied live on the next transmit; RX restart is the caller's choice.
    RadioConfig& config() { return cfg_; }

private:
    void superviseLoop();
    void readPipe(int fd);
    std::vector<std::string> rxArgv() const;

    RadioConfig cfg_;
    PacketHandler handler_;
    std::thread reader_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> rx_count_{0}, tx_count_{0};
    std::atomic<double> last_rx_time_{0.0};
    pid_t rx_pid_ = -1;
    int rx_fd_ = -1;
};
