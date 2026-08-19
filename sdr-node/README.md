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

**Implemented:** channel (group) chat both directions; direct (private)
messages with end-to-end ECDH encryption, automatic ACKs and delivery
confirmations; directed routing (paths learned from PATH returns, DMs go
direct once a route is known, flood otherwise); contacts from adverts,
persisted; periodic + manual self adverts; radio/core stats; live radio
retune from the app. Works with both meshcore-open and the official app
(every reply byte-verified against the real firmware source).

Repeater administration works too: login (ANON_REQ carrying our public
key, so a repeater can answer a node it has never met), status requests,
and the CLI console - each an encrypted request whose RESPONSE is matched
back to the pending command, including responses that arrive folded into
a PATH return.

Trace paths work: the app's path-trace map can probe a route and get the
per-hop SNRs back.

Node discovery works (zero-hop CONTROL packets, so only direct neighbours
answer), including the follow-up "request name": an anonymous request
(CMD 57) carries our full public key so a node we have never met can
derive the shared secret and reply, and the answer is matched back by tag, and GRP_DATA blobs - the transport the app uses for images - are
carried both ways. DEVICE_INFO reports feature level 13, matching firmware
v1.17.1, because everything that level gates is implemented.

**Not yet:** acting as a repeater (deliberately - at ~25 mW it would be a
weak one, and it would double the node's airtime).

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

## Running as a service

The macmini deployment runs under systemd (`/etc/systemd/system/
meshcore-sdr-node.service`, Restart=always, logs appended to
`~/sdr-node.log`) so the node survives crashes and reboots; the laptop
reaches it through a LaunchAgent-managed ssh tunnel
(`~/Library/LaunchAgents/net.mmm.sdr-tunnel.plist`, local port 5001 -
macOS AirPlay squats on 5000).

## Testing

`ctest` runs the whole protocol surface against fake radios - no SDR, no
mesh, a couple of seconds:

```bash
cd build && ctest --output-on-failure
```

The test drives the real daemon over a real socket, speaking the app's
exact framing, and walks the connect handshake field by field, channel
sync, the offline queue, contacts, channel and direct messages, delivery
ACKs, routing (a PATH return must teach a route and the next message must
radiate over it), traces, discovery, channel data and anonymous requests -
asserting on the bytes actually handed to the transmitter. 87 assertions.

Packets injected into the fake receiver are built by the real encoder, and
"transmitted" packets are decoded back with the real decoder, so a change
that breaks the wire format fails the test rather than the mesh.

## Notes and limits

- One app client at a time; a new connection replaces the old one.
- `SET_RADIO_PARAMS` retunes the transmitter immediately and appends the
  new frequency to the receiver's channel list, bouncing `lora_rx` to pick
  it up. The RX side can watch several channels and spreading factors at
  once, which a real SX1262 node cannot.
- Anonymous requests (the "request name" flow) are sent direct, never
  flood: repeaters guard every non-login `ANON_REQ_TYPE_*` branch with
  `isRouteDirect()` and silently drop flood-routed ones.
- Delivery receipts and trace results are single unacknowledged packets. At
  these power levels a lost one looks exactly like a timeout even though
  the message itself arrived.
- At ~25 mW EIRP the node is heard by nearby repeaters but is not a
  long-range station; `tx_vga`/`tx_amp` are already at the HackRF maximum.
- The RTL-SDR hears the HackRF's own transmissions; the daemon dedups them
  (as it dedups mesh flood rebroadcasts) by payload within a 10-minute window.
- Duty cycle: `lora_tx` enforces `tx_duty` (default 10%, the EU 869.4-869.65
  figure) by idling after each frame - a long message on SF11/12 can make
  the *next* send wait. Keep the TX channel inside that sub-band or lower
  `tx_duty` to 1.
- Battery/storage are cosmetic answers (mains powered); stats/telemetry/
  repeater login are not implemented.
