#!/usr/bin/env python3
"""End-to-end protocol test for meshcore-sdr-node with fake radios.

Speaks the companion protocol exactly as the meshcore-open app does
(0x3C/0x3E framing, LE u16 length) and walks the connect handshake, channel
sync, message sync, and a channel send. The fake lora_rx replays two test
packets; the fake lora_tx records its command line, and this test decodes
the transmitted hex to prove it is a valid encrypted GroupText.
"""
import socket, struct, subprocess, sys, time, os, tempfile, shutil

NODE = sys.argv[1]          # path to meshcore-sdr-node
PACKETGEN = sys.argv[2]     # path to make_test_packets
DECODER_CLI = sys.argv[3] if len(sys.argv) > 3 else None
PORT = 51555
PUB_KEY = "8b3387e9c5cdea6ac9e5edbaa115cd72"

td = tempfile.mkdtemp()
fails = []

def check(cond, what):
    print(("PASS: " if cond else "FAIL: ") + what)
    if not cond:
        fails.append(what)

# --- Fixed node identity (so the incoming DM can be pre-encrypted for it) ---
NODE_SEED = "4444444444444444444444444444444444444444444444444444444444444444"
node_pub = None
if DECODER_CLI:
    out = subprocess.run([DECODER_CLI, "derive-key", NODE_SEED + NODE_SEED],
                         capture_output=True, text=True).stdout
    import re as _re
    for ln in out.splitlines():
        ln = _re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
        if _re.fullmatch(r"[0-9A-Fa-f]{64}", ln):
            node_pub = ln.lower()   # the standalone 64-hex line is the pubkey
with open(os.path.join(td, "identity.key"), "w") as f:
    f.write(NODE_SEED + (node_pub or NODE_SEED) + "\n")

# --- Test packets from the real encoder ---
packets = {}
gen_args = [PACKETGEN] + ([node_pub] if node_pub else [])
for line in subprocess.run(gen_args, capture_output=True, text=True).stdout.splitlines():
    k, v = line.split()
    packets[k] = v.lower()

# --- Fake radios ---
rx_log = os.path.join(td, "rx_feed.txt")
with open(rx_log, "w") as f:
    f.write(f"rx cfg: freq=869618000 sf=7 bw=62500 snr=5.5 cfo=0.10 time={time.time():.3f}\n")
    f.write(f"rx ok: {packets['GROUPTEXT']}\n")
    f.write(f"rx cfg: freq=869618000 sf=7 bw=62500 snr=-2.0 cfo=0.20 time={time.time():.3f}\n")
    f.write(f"rx ok: {packets['ADVERT']}\n")

fake_rx = os.path.join(td, "fake_lora_rx")
with open(fake_rx, "w") as f:
    f.write(f"#!/bin/sh\n# ignore args; follow the feed so the test can inject packets mid-run\nsleep 2\ntail -f {rx_log}\n")
fake_tx = os.path.join(td, "fake_lora_tx")
tx_record = os.path.join(td, "tx_record.txt")
with open(fake_tx, "w") as f:
    f.write(f"#!/bin/sh\necho \"$@\" >> {tx_record}\nexit 0\n")
os.chmod(fake_rx, 0o755)
os.chmod(fake_tx, 0o755)

# --- Daemon config ---
conf = os.path.join(td, "sdr-node.conf")
with open(conf, "w") as f:
    f.write(f"""name = SDR Test Node
port = {PORT}
identity_file = {td}/identity.key
channels_file = {td}/channels.txt
contacts_file = {td}/contacts.txt
rx_binary = {fake_rx}
tx_binary = {fake_tx}
rx_channels = 869618000
rx_sfs = 7
tx_freq = 869618000
tx_sf = 7
""")
with open(os.path.join(td, "channels.txt"), "w") as f:
    f.write(f"Public,{PUB_KEY}\n")
if "PEERPUB" in packets:
    with open(os.path.join(td, "contacts.txt"), "w") as f:
        f.write(f"{packets['PEERPUB']}\t1\t1787090000\t1787090000\t0\t0\tTestPeer DM\n")

daemon = subprocess.Popen([NODE, "-c", conf], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
import atexit
atexit.register(daemon.kill)
time.sleep(0.7)

def frame(payload: bytes) -> bytes:
    return bytes([0x3C, len(payload) & 0xFF, len(payload) >> 8]) + payload

class Client:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        self.buf = b""
    def send(self, payload: bytes):
        self.s.sendall(frame(payload))
    def recv(self, timeout=5.0) -> bytes:
        self.s.settimeout(timeout)
        while True:
            while len(self.buf) >= 3:
                if self.buf[0] != 0x3E:
                    self.buf = self.buf[1:]
                    continue
                ln = self.buf[1] | (self.buf[2] << 8)
                if len(self.buf) < 3 + ln:
                    break
                p = self.buf[3:3 + ln]
                self.buf = self.buf[3 + ln:]
                return p
            self.buf += self.s.recv(4096)

c = Client()
pushes = []

def recv_resp(timeout=5.0) -> bytes:
    # The daemon interleaves async pushes (codes >= 0x80) with command
    # responses, exactly like real firmware; collect them separately.
    while True:
        p = c.recv(timeout)
        if p and p[0] >= 0x80:
            pushes.append(p)
            continue
        return p

time.sleep(0.3)   # app-side listener-attach delay

# 1. DEVICE_QUERY -> DEVICE_INFO
c.send(bytes([22, 4]))
r = recv_resp()
check(r[0] == 13 and len(r) >= 82, "DEVICE_INFO (code 13, 82 bytes)")
max_channels = r[3]
check(max_channels == 8, "max_channels = 8")

# 2. APP_START -> SELF_INFO
c.send(bytes([1, 1, 0, 0, 0, 0, 0, 0]) + b"MeshCoreOpen\x00")
r = recv_resp()
check(r[0] == 5 and len(r) >= 58, "SELF_INFO (code 5, >=58 bytes)")
pubkey = r[4:36]
check(sum(1 for b in pubkey if b == 0) <= 16, "self pubkey looks real")
freq, bw = struct.unpack_from("<II", r, 48)
check(freq == 869618000 and bw == 62500, f"radio params in SELF_INFO ({freq}, {bw})")
name = r[58:].split(b"\x00")[0].decode()
check(name == "SDR Test Node", f"node name '{name}'")

# 3. Channel sync
c.send(bytes([31, 0]))
r = recv_resp()
check(r[0] == 18 and len(r) >= 50, "CHANNEL_INFO idx 0")
chname = r[2:34].split(b"\x00")[0].decode()
psk = r[34:50].hex()
check(chname == "Public" and psk == PUB_KEY, "channel 0 name+psk")
for i in range(1, max_channels):
    c.send(bytes([31, i]))
    r = recv_resp()
    check(r[0] == 18 and len(r) >= 50, f"CHANNEL_INFO idx {i} (empty slot)") if i == 1 else None

# 3b. Past the end: firmware parity requires ERR not-found, or the official
# app's scan-until-error channel loop never terminates
c.send(bytes([31, max_channels])); r = recv_resp()
check(r[0] == 1 and len(r) >= 2 and r[1] == 2, "CHANNEL_INFO past max -> ERR not_found")
# 3c. Setters answer RESP_OK like real firmware
c.send(bytes([6]) + struct.pack("<I", int(time.time()))); r = recv_resp()
check(r[0] == 0, "SET_DEVICE_TIME -> OK")

# 4. Message sync: fake rx feed delivers a GroupText ~2 s after daemon start
time.sleep(2.5)
c.send(bytes([10]))
r = recv_resp()
check(r[0] == 8, "queued channel message delivered (code 8)")
if r[0] == 8:
    check(r[1] == 0, "on channel 0")
    text = r[8:].split(b"\x00")[0].decode()
    check(text == "TestPeer: hello from the fake mesh", f"message text '{text}'")
c.send(bytes([10]))
r = recv_resp()
check(r[0] == 10, "NO_MORE_MESSAGES after queue drained")

# 5. Contacts: the advert should have created one
c.send(bytes([4]))
r = recv_resp()
check(r[0] == 2, "CONTACTS_START")
contact_names = []
while True:
    r = recv_resp()
    if r[0] == 4:
        break
    check(r[0] == 3 and len(r) == 148, "contact frame is 148 bytes")
    contact_names.append(r[100:132].split(b"\x00")[0].decode())
expected = {"FakeNode"} | ({"TestPeer DM"} if "PEERPUB" in packets else set())
check(set(contact_names) == expected, f"contacts synced: {sorted(contact_names)}")

# 5b. Rename with a trailing NUL, as the official app sends it; the NUL must
# not survive into the name (it would truncate every on-air message)
c.send(bytes([8]) + b"NulName\x00")
r = recv_resp()
check(r[0] == 0, "SET_ADVERT_NAME (NUL-terminated) -> OK")

# 6. Send a channel message -> RESP_SENT + fake lora_tx invoked with valid packet
c.send(bytes([3, 0, 0]) + struct.pack("<I", int(time.time())) + b"ahoj z testu\x00")
r = recv_resp()
check(r[0] == 0, "channel send answered with RESP_OK (firmware parity)")
time.sleep(0.5)
sent_hex = None
with open(tx_record) as f:
    args = f.read().split()
    if "-x" in args:
        sent_hex = args[args.index("-x") + 1]
check(sent_hex is not None, "lora_tx invoked with -x <hex>")
if sent_hex and DECODER_CLI:
    out = subprocess.run([DECODER_CLI, sent_hex, "-k", PUB_KEY],
                         capture_output=True, text=True).stdout
    check("ahoj z testu" in out, "transmitted packet decrypts to the sent text")
    check("NulName" in out, "on-air message carries the (renamed) node name prefix")

# 6b. Direct message flow (only when the decoder CLI gave us the node pubkey)
if "DM" in packets:
    with open(rx_log, "a") as f:
        f.write(f"rx cfg: freq=869618000 sf=7 bw=62500 snr=3.0 cfo=0.00 time={time.time():.3f}\n")
        f.write(f"rx ok: {packets['DM']}\n")
    # incoming DM -> MSG_WAITING push -> pull -> code 16 frame
    got_dm = None
    deadline = time.time() + 6
    while time.time() < deadline and got_dm is None:
        try:
            p = c.recv(1.0)
        except socket.timeout:
            c.send(bytes([10]))
            continue
        if p and p[0] >= 0x80:
            pushes.append(p)
            if p[0] == 0x83:
                c.send(bytes([10]))
        elif p and p[0] == 16:
            got_dm = p
        elif p and p[0] == 10:
            pass
    check(got_dm is not None, "incoming DM delivered as code-16 frame")
    if got_dm:
        prefix = got_dm[4:10].hex()
        check(prefix == packets["PEERPUB"][:12], "DM sender prefix matches peer")
        text = got_dm[16:].split(b"\x00")[0].decode()
        check(text == "sukromny pozdrav", f"DM text '{text}'")
    time.sleep(0.8)
    ack_tx = None
    with open(tx_record) as f:
        for line in f:
            args2 = line.split()
            if "-x" in args2:
                hx = args2[args2.index("-x") + 1]
                b = bytes.fromhex(hx)
                if (b[0] >> 2) & 0x0F == 0x08:
                    ack_tx = b
    check(ack_tx is not None, "PATH return (with ACK) transmitted for the flood DM")

    # outgoing DM: [2][type][attempt][ts4][prefix6][text]
    c.send(bytes([2, 0, 0]) + struct.pack("<I", int(time.time())) +
           bytes.fromhex(packets["PEERPUB"][:12]) + b"odpoved\x00")
    r = recv_resp()
    check(r[0] == 6 and len(r) >= 10, "RESP_SENT for direct send")
    sent_ack = struct.unpack_from("<I", r, 2)[0] if len(r) >= 10 else 0
    check(sent_ack != 0, "expected ack hash is nonzero")
    time.sleep(0.8)
    dm_tx = None
    with open(tx_record) as f:
        for line in f:
            args2 = line.split()
            if "-x" in args2:
                hx = args2[args2.index("-x") + 1]
                b = bytes.fromhex(hx)
                if (b[0] >> 2) & 0x0F == 0x02:
                    dm_tx = b
    check(dm_tx is not None, "outgoing DM packet was transmitted")
    if dm_tx:
        check(dm_tx[2] == bytes.fromhex(packets["PEERPUB"])[0], "DM dest hash = peer")
    # inject the delivery ACK -> PUSH_SEND_CONFIRMED with the same hash
    ack_pkt = bytes([0x0D, 0x00]) + struct.pack("<I", sent_ack) + b"\x00\x42"
    with open(rx_log, "a") as f:
        f.write(f"rx cfg: freq=869618000 sf=7 bw=62500 snr=1.0 cfo=0.00 time={time.time():.3f}\n")
        f.write(f"rx ok: {ack_pkt.hex()}\n")
    got_confirm = False
    deadline = time.time() + 5
    while time.time() < deadline and not got_confirm:
        try:
            p = c.recv(1.0)
        except socket.timeout:
            continue
        if p and p[0] == 0x82 and struct.unpack_from("<I", p, 1)[0] == sent_ack:
            got_confirm = True
        elif p and p[0] >= 0x80:
            pushes.append(p)
    check(got_confirm, "PUSH_SEND_CONFIRMED with matching ack hash")

# 6c. Routing: a PATH return teaches the out-path and confirms delivery
if "DM" in packets:
    c.send(bytes([2, 0, 0]) + struct.pack("<I", int(time.time())) +
           bytes.fromhex(packets["PEERPUB"][:12]) + b"druha sprava\x00")
    r = recv_resp()
    check(r[0] == 6 and r[1] == 1, "second DM sent as flood (no path yet)")
    ack2 = struct.unpack_from("<I", r, 2)[0]
    out = subprocess.run(gen_args + [struct.pack("<I", ack2).hex()],
                         capture_output=True, text=True).stdout
    pathpkt = dict(l.split() for l in out.splitlines())["PATHPKT"].lower()
    with open(rx_log, "a") as f:
        f.write(f"rx cfg: freq=869618000 sf=7 bw=62500 snr=4.0 cfo=0.00 time={time.time():.3f}\n")
        f.write(f"rx ok: {pathpkt}\n")
    got_pathupd = got_confirm2 = False
    deadline = time.time() + 6
    while time.time() < deadline and not (got_pathupd and got_confirm2):
        try:
            p = c.recv(1.0)
        except socket.timeout:
            continue
        if p and p[0] == 0x81 and p[1:33].hex() == packets["PEERPUB"]:
            got_pathupd = True
        elif p and p[0] == 0x82 and struct.unpack_from("<I", p, 1)[0] == ack2:
            got_confirm2 = True
        elif p and p[0] >= 0x80:
            pushes.append(p)
    check(got_pathupd, "PUSH_PATH_UPDATED after PATH return")
    check(got_confirm2, "delivery confirmed from the ACK inside the PATH return")

    # With a path learned, the next DM goes out direct-routed over it
    c.send(bytes([2, 0, 0]) + struct.pack("<I", int(time.time())) +
           bytes.fromhex(packets["PEERPUB"][:12]) + b"tretia sprava\x00")
    r = recv_resp()
    check(r[0] == 6 and r[1] == 0, "third DM reported as direct (path known)")
    time.sleep(0.8)
    direct_tx = None
    with open(tx_record) as f:
        for line in f:
            args2 = line.split()
            if "-x" in args2:
                b = bytes.fromhex(args2[args2.index("-x") + 1])
                if (b[0] >> 2) & 0x0F == 0x02 and (b[0] & 3) == 2:
                    direct_tx = b
    check(direct_tx is not None and direct_tx[1] == 2 and direct_tx[2:4] == b"\xaa\xbb",
          "direct DM carries the learned path aa,bb")

    # RESET_PATH falls back to flood
    c.send(bytes([13]) + bytes.fromhex(packets["PEERPUB"]))
    r = recv_resp()
    check(r[0] == 0, "RESET_PATH -> OK")
    c.send(bytes([2, 0, 0]) + struct.pack("<I", int(time.time())) +
           bytes.fromhex(packets["PEERPUB"][:12]) + b"stvrta sprava\x00")
    r = recv_resp()
    check(r[0] == 6 and r[1] == 1, "post-reset DM sent as flood again")

# 7. Unknown command -> RESP_ERR, daemon stays alive
c.send(bytes([99]))
r = recv_resp()
check(r[0] == 1, "unknown command answered with RESP_ERR")

# 8. Pushes collected along the way: MSG_WAITING after RX, NEW_ADVERT contact
check(any(p[0] == 0x83 for p in pushes), "PUSH_MSG_WAITING was sent on RX")
check(any(p[0] == 0x8A and len(p) == 148 for p in pushes), "PUSH_NEW_ADVERT (148B) was sent")

daemon.terminate()
shutil.rmtree(td)
print(f"\n{'ALL PASS' if not fails else str(len(fails)) + ' FAILURES'}")
sys.exit(1 if fails else 0)
