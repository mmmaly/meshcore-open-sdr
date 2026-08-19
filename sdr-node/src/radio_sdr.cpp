#include "radio_sdr.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

// fork/exec with stdout piped back; stderr goes to the daemon's stderr so
// receiver diagnostics stay visible in the daemon log.
static pid_t spawn_pipe(const std::vector<std::string>& argv, int* out_fd) {
    int fds[2];
    if (pipe(fds) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
#ifdef __linux__
        // If the daemon dies without a clean stop (kill -9, crash, _exit
        // from a signal handler), the receiver must not linger holding the
        // dongle - the next daemon's lora_rx would fail to claim it.
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() == 1) _exit(0);   // parent already gone
#endif
        std::vector<char*> args;
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        execvp(args[0], args.data());
        perror("execvp");
        _exit(127);
    }
    close(fds[1]);
    *out_fd = fds[0];
    return pid;
}

std::vector<std::string> SdrRadio::rxArgv() const {
    std::vector<std::string> argv = {cfg_.rx_binary};
    if (!cfg_.rx_channels.empty()) { argv.push_back("-C"); argv.push_back(cfg_.rx_channels); }
    if (!cfg_.rx_sfs.empty())      { argv.push_back("-S"); argv.push_back(cfg_.rx_sfs); }
    argv.push_back("-b"); argv.push_back(std::to_string(cfg_.bw));
    argv.push_back("-p"); argv.push_back(std::to_string(cfg_.rx_ppm));
    if (cfg_.rx_agc) { argv.push_back("-G"); argv.push_back("-T"); }
    if (!cfg_.rx_device.empty()) { argv.push_back("-d"); argv.push_back(cfg_.rx_device); }
    return argv;
}

bool SdrRadio::start(PacketHandler handler) {
    if (running_) return true;
    handler_ = std::move(handler);
    running_ = true;
    reader_ = std::thread(&SdrRadio::superviseLoop, this);
    return true;
}

// Keep a receiver alive for the daemon lifetime: respawn lora_rx when it
// dies (USB glitch, dongle claim race after an unclean restart, crash).
void SdrRadio::superviseLoop() {
    while (running_) {
        int fd = -1;
        auto argv = rxArgv();
        pid_t pid = spawn_pipe(argv, &fd);
        if (pid < 0) {
            fprintf(stderr, "[radio] failed to spawn lora_rx\n");
        } else {
            rx_pid_ = pid;
            rx_fd_ = fd;
            std::string cmd;
            for (const auto& a : argv) cmd += a + " ";
            fprintf(stderr, "[radio] rx started (pid %d): %s\n", (int)pid, cmd.c_str());
            readPipe(fd);
            int status = 0;
            waitpid(pid, &status, 0);
            rx_pid_ = -1;
        }
        if (running_) {
            fprintf(stderr, "[radio] lora_rx exited; restarting in 5 s\n");
            for (int i = 0; i < 50 && running_; i++) usleep(100 * 1000);
        }
    }
}

void SdrRadio::stop() {
    if (!running_) return;
    running_ = false;
    if (rx_pid_ > 0) {
        kill(rx_pid_, SIGTERM);
        waitpid(rx_pid_, nullptr, 0);
        rx_pid_ = -1;
    }
    if (reader_.joinable()) reader_.join();
}

// Parse the lora_rx stdout contract. The "rx cfg:" line always precedes the
// "rx ok:" line of the same frame (that pairing is what dekoduj-* scripts and
// meshcore-decoder stream already rely on).
void SdrRadio::readPipe(int fd) {
    FILE* f = fdopen(fd, "r");
    if (!f) { close(fd); return; }
    char line[16384];
    RxPacket pending{};
    bool have_cfg = false;
    while (running_ && fgets(line, sizeof(line), f)) {
        if (strncmp(line, "rx cfg:", 7) == 0) {
            RxPacket p{};
            unsigned freq = 0, bw = 0;
            int sf = 0;
            float snr = 0, cfo = 0;
            double t = 0;
            if (sscanf(line, "rx cfg: freq=%u sf=%d bw=%u snr=%f cfo=%f time=%lf",
                       &freq, &sf, &bw, &snr, &cfo, &t) >= 5) {
                p.freq = freq; p.sf = sf; p.bw = bw; p.snr = snr; p.cfo = cfo; p.time = t;
                pending = p;
                have_cfg = true;
            }
        } else if (strncmp(line, "rx ok: ", 7) == 0) {
            std::string hex(line + 7);
            while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r' || hex.back() == ' '))
                hex.pop_back();
            if (!hex.empty()) {
                RxPacket p = have_cfg ? pending : RxPacket{};
                p.hex = hex;
                rx_count_++;
                last_rx_time_ = p.time;
                if (handler_) handler_(p);
            }
            have_cfg = false;
        }
    }
    fclose(f);
}

bool SdrRadio::transmit(const std::string& hex) {
    std::vector<std::string> argv = {
        cfg_.tx_binary,
        "-f", std::to_string(cfg_.tx_freq),
        "-S", std::to_string(cfg_.tx_sf),
        "-b", std::to_string(cfg_.bw),
        "-c", std::to_string(cfg_.tx_cr),
        "-p", std::to_string(cfg_.tx_ppm),
        "-g", std::to_string(cfg_.tx_vga),
        "-y", std::to_string(cfg_.tx_duty),
        "-x", hex,
    };
    if (cfg_.tx_amp) argv.insert(argv.end() - 2, "-a");
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        // lora_tx logs to stderr; keep it in the daemon log
        std::vector<char*> args;
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        execvp(args[0], args.data());
        perror("execvp");
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (ok) tx_count_++;
    else fprintf(stderr, "[radio] lora_tx failed (status %d)\n", status);
    return ok;
}
