#include "companion_server.h"
#include "node.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static constexpr uint8_t FRAME_TO_NODE = 0x3C;   // '<'
static constexpr uint8_t FRAME_TO_APP = 0x3E;    // '>'
static constexpr size_t MAX_PAYLOAD = 172;

void CompanionServer::sendFrame(int fd, const std::vector<uint8_t>& payload) {
    if (payload.empty() || payload.size() > MAX_PAYLOAD) {
        fprintf(stderr, "[server] refusing to send %zu-byte frame\n", payload.size());
        return;
    }
    std::lock_guard<std::mutex> lk(tx_mtx_);
    uint8_t hdr[3] = {FRAME_TO_APP,
                      (uint8_t)(payload.size() & 0xFF),
                      (uint8_t)(payload.size() >> 8)};
    if (write(fd, hdr, 3) != 3 ||
        write(fd, payload.data(), payload.size()) != (ssize_t)payload.size()) {
        // Client is gone; the read loop will notice and clean up
    }
}

void CompanionServer::serveClient(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    auto sender = [this, fd](const std::vector<uint8_t>& payload) {
        sendFrame(fd, payload);
    };

    // The app attaches its frame listener ~200 ms after connecting; frames
    // sent before that are lost. Pushes are held back until the app has
    // spoken first (its handshake commands arrive after the listener is up).
    bool app_spoke = false;

    std::vector<uint8_t> buf;
    uint8_t chunk[4096];
    while (running_) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        buf.insert(buf.end(), chunk, chunk + n);

        size_t pos = 0;
        while (buf.size() - pos >= 3) {
            if (buf[pos] != FRAME_TO_NODE) { pos++; continue; }   // resync
            size_t len = buf[pos + 1] | ((size_t)buf[pos + 2] << 8);
            if (len > MAX_PAYLOAD) { pos++; continue; }           // false sync
            if (buf.size() - pos < 3 + len) break;                // incomplete
            std::vector<uint8_t> frame(buf.begin() + pos + 3,
                                       buf.begin() + pos + 3 + len);
            pos += 3 + len;

            if (!app_spoke) {
                app_spoke = true;
                node_.setAppSender(sender);
            }
            node_.handleCommand(frame, sender);
        }
        buf.erase(buf.begin(), buf.begin() + pos);
    }
    node_.setAppSender(nullptr);
    close(fd);
    fprintf(stderr, "[server] client disconnected\n");
}

void CompanionServer::run() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port_);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 2) != 0) {
        perror("[server] bind/listen");
        return;
    }
    fprintf(stderr, "[server] listening on port %d\n", port_);
    while (running_) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int fd = accept(srv, (sockaddr*)&peer, &plen);
        if (fd < 0) continue;
        char ip[64];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        fprintf(stderr, "[server] client connected from %s\n", ip);
        serveClient(fd);   // one client at a time
    }
    close(srv);
}
