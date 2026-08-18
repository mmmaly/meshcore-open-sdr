# meshcore-sdr-node

A MeshCore node whose radio is a pair of SDRs: an **RTL-SDR receives**, a
**HackRF transmits**. The [meshcore-open](../README.md) app connects to it
over TCP (the app's existing TCP screen — nothing app-side to install), so
your phone can chat on a real MeshCore mesh through the SDRs on a host
machine.

```
phone / desktop app ──TCP:5000──> meshcore-sdr-node ──┬── lora_rx (RTL-SDR)   RX
       (meshcore-open)             (this daemon)      └── lora_tx (HackRF)    TX
```

The daemon implements the companion-radio protocol (the same `0x3C/0x3E`
framing as MeshCore USB serial): device/self info, time sync, channel list
management, the offline-message queue, contact tracking, and channel
messaging. Mesh packets are built and parsed by
[meshcore-cpp-decoder](https://github.com/mmmaly/meshcore-cpp-decoder);
LoRa modulation/demodulation is
[LoraReceiverStandalone](https://github.com/mmmaly/LoraReceiverStandalone)'s
`lora_rx`/`lora_tx`, run as child processes so a receiver crash never takes
the node down.

**V1 scope:** channel (group) chat in both directions, self adverts, and
contacts learned from heard adverts. Direct (private) messages need X25519
contact crypto that meshcore-cpp-decoder does not have yet; the daemon
answers those with "unsupported" so the app shows a clean failure.

## Build

```bash
# needs: cmake, OpenSSL, and sibling checkouts of meshcore-cpp-decoder
# (or -DDECODER_DIR=...) plus built lora_rx/lora_tx binaries
cd sdr-node && mkdir build && cd build
cmake .. && make -j
ctest        # protocol end-to-end test with fake radios, no hardware needed
```

## Run

```bash
cp sdr-node.conf.example sdr-node.conf   # edit: radio devices, ppm, name
./build/meshcore-sdr-node -c sdr-node.conf -a   # -a = advertise on startup
```

- A fresh Ed25519 identity is generated into `identity_file` on first run
  (mode 600). Back it up — it *is* your node's identity.
- `channels_file` holds `name,keyhex` per line; the daemon seeds channel 0
  with whatever you put there (e.g. `Public,8b3387e9c5cdea6ac9e5edbaa115cd72`)
  and the app can add/edit channels, which persist back to the file.
  Keep this file out of git.
- In the app: **Connect via TCP** → host = the daemon machine, port 5000.

## Notes and limits

- One app client at a time; a new connection replaces the old one.
- `SET_RADIO_PARAMS` from the app retunes the **transmit** side immediately;
  the receiver keeps its configured channel fan-out until the daemon is
  restarted (the RX side can watch several channels/SFs at once, which a
  real SX1262 node cannot).
- The RTL-SDR hears the HackRF's own transmissions; the daemon dedups them
  (as it dedups mesh flood rebroadcasts) by payload within a 10-minute window.
- Duty cycle: `lora_tx` enforces `tx_duty` (default 10%, the EU 869.4-869.65
  figure) by idling after each frame - a long message on SF11/12 can make
  the *next* send wait. Keep the TX channel inside that sub-band or lower
  `tx_duty` to 1.
- Battery/storage are cosmetic answers (mains powered); stats/telemetry/
  repeater login are not implemented.
