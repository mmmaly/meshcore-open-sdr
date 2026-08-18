// TCP server speaking the MeshCore companion framing: every frame is
// [start][len_lo][len_hi][payload], length little-endian, payload <= 172
// bytes. App->node frames start 0x3C ('<'), node->app frames 0x3E ('>').
// One client at a time; a new connection replaces the old one.
#pragma once

#include <cstdint>
#include <vector>
#include <atomic>
#include <mutex>

class Node;

class CompanionServer {
public:
    CompanionServer(Node& node, int port) : node_(node), port_(port) {}

    // Blocks forever: accept loop. Call from main thread.
    void run();
    void stop() { running_ = false; }

private:
    void serveClient(int fd);
    void sendFrame(int fd, const std::vector<uint8_t>& payload);

    Node& node_;
    int port_;
    std::atomic<bool> running_{true};
    std::mutex tx_mtx_;   // pushes come from the radio thread
};
