// P2P File Transfer — STUN-only WebRTC, manual signaling.
//
// Flow:
//   sender:   pick file -> stream-hash sha256 -> create PeerConnection ->
//             1 control DC + 4 data DCs -> createOffer -> wait ICE complete ->
//             pack(offer + meta) into URL hash -> show link/QR ->
//             wait for receiver's answer paste -> setRemoteDescription ->
//             once channels open: send meta over ctrl, wait ack, push chunks
//             round-robin across 4 data channels with [chunkId u32 BE][payload].
//
//   receiver: parse URL hash -> unpack offer+meta -> show meta + Download btn ->
//             on click: create PC, pc.ondatachannel collects ctrl + 4 data ->
//             setRemoteDescription(offer) -> createAnswer -> wait ICE ->
//             pack(answer) -> show code/QR for sender to paste back ->
//             on connect: receive meta over ctrl, reply ack, accept frames,
//             reassemble (File System Access API if available, else Blob[]),
//             verify sha256 against meta.hash.
//
// No TURN. If ICE fails (symmetric NAT/CGNAT/strict firewall) we surface the
// error and stop — no relay fallback by design.

'use strict';

// ---------- Constants ----------
const ICE_SERVERS  = [{ urls: 'stun:stun.cloudflare.com:3478' }];
const CHUNK_SIZE   = 64 * 1024;
const BUF_HIGH     = 16 * 1024 * 1024;
const BUF_LOW      = 1  * 1024 * 1024;
const STREAMS      = 4;
const HASH_BLOCK   = 1 * 1024 * 1024;
const ICE_TIMEOUT  = 5000;
const HEADER_LEN   = 4; // uint32 BE chunkId

// ---------- DOM ----------
const $ = (id) => document.getElementById(id);
const senderView   = $('senderView');
const receiverView = $('receiverView');
const logEl        = $('log');

// ---------- Logging ----------
function log(msg, level = 'info') {
  const line = document.createElement('div');
  line.className = level;
  const ts = new Date().toISOString().slice(11, 23);
  line.textContent = `[${ts}] ${msg}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
  // eslint-disable-next-line no-console
  console.log(`[${level}]`, msg);
}
$('clearLog').onclick = () => { logEl.innerHTML = ''; };

// ---------- Format helpers ----------
function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(2)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}
function fmtSpeed(bytes, ms) {
  if (ms <= 0) return '0 B/s';
  return `${fmtBytes((bytes * 1000) / ms)}/s`;
}

// ---------- SDP minification ----------
//
// WebRTC SDP for a datachannel-only session is mostly boilerplate. We keep
// only the dynamic fields and reconstruct a canonical SDP on the receiver.
// Brings a ~3 KB SDP down to ~300-500 bytes BEFORE compression.
//
// Compact form:
//   { t, u, p, f, s, c[], m? }
//     t — 'o' for offer, 'a' for answer
//     u — ice-ufrag
//     p — ice-pwd
//     f — DTLS sha-256 fingerprint, hex, no colons (64 chars)
//     s — setup: 'a' (actpass on offer / active on answer), 'p' (passive)
//     c — array of candidate strings (verbatim, without "a=candidate:" prefix)
//     m — optional max-message-size (defaults to 262144)
function compactSdp(desc) {
  const sdp = desc.sdp;
  const get = (re) => {
    const m = re.exec(sdp);
    if (!m) throw new Error(`SDP missing ${re}`);
    return m[1];
  };
  const ufrag = get(/a=ice-ufrag:(\S+)/);
  const pwd = get(/a=ice-pwd:(\S+)/);
  const fp = get(/a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/).replace(/:/g, '').toLowerCase();
  const setup = get(/a=setup:(\S+)/);
  const maxMsgMatch = /a=max-message-size:(\d+)/.exec(sdp);

  // Strip optional tail attributes that peer's ICE agent does not need:
  //   generation N    — purely informational (renomination counter)
  //   network-id N    — informational, used by Chrome for stats
  //   network-cost N  — local preference hint, not on the wire
  //   ufrag X         — session-level ice-ufrag already covers this
  //   raddr 0.0.0.0   — anonymized related address (mDNS mode), peer ignores
  //   raddr ::        — same, IPv6 anonymized
  //
  // Doing this before deflate gives a much bigger win than relying on the
  // compressor alone, because each candidate line has these tails repeated
  // with slightly different numeric values, which DEFLATE can't share.
  function stripCand(line) {
    let s = line;
    s = s.replace(/\s+generation\s+\d+/g, '');
    s = s.replace(/\s+network-id\s+\d+/g, '');
    s = s.replace(/\s+network-cost\s+\d+/g, '');
    s = s.replace(/\s+ufrag\s+\S+/g, '');
    s = s.replace(/\s+raddr\s+(?:0\.0\.0\.0|::)\s+rport\s+0/g, '');
    return s;
  }

  const candidates = [];
  const rx = /a=candidate:([^\r\n]+)/g;
  let cm;
  while ((cm = rx.exec(sdp)) !== null) candidates.push(stripCand(cm[1]));

  const out = {
    t: desc.type === 'offer' ? 'o' : 'a',
    u: ufrag,
    p: pwd,
    f: fp,
    s: setup === 'passive' ? 'p' : 'a',
    c: candidates,
  };
  if (maxMsgMatch && +maxMsgMatch[1] !== 262144) out.m = +maxMsgMatch[1];
  return out;
}

function expandSdp(c) {
  if (c.f.length !== 64 || !/^[0-9a-f]+$/.test(c.f)) throw new Error('Bad fingerprint');
  const fp = c.f.match(/.{2}/g).join(':').toUpperCase();
  const type = c.t === 'o' ? 'offer' : 'answer';
  const setup = c.s === 'p' ? 'passive' : (type === 'offer' ? 'actpass' : 'active');
  const maxMsg = c.m || 262144;

  const lines = [
    'v=0',
    'o=- 1 1 IN IP4 0.0.0.0',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0',
    'a=msid-semantic: WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
    'c=IN IP4 0.0.0.0',
    `a=ice-ufrag:${c.u}`,
    `a=ice-pwd:${c.p}`,
    'a=ice-options:trickle',
    `a=fingerprint:sha-256 ${fp}`,
    `a=setup:${setup}`,
    'a=mid:0',
    'a=sctp-port:5000',
    `a=max-message-size:${maxMsg}`,
  ];
  for (const cand of c.c || []) lines.push(`a=candidate:${cand}`);
  return { type, sdp: lines.join('\r\n') + '\r\n' };
}

// ---------- pack/unpack: JSON -> deflate-raw -> base64url ----------
//
// The 'sdp' field inside the input object (if present) is compacted to its
// minimal form before serialization. On unpack, it is expanded back. Other
// fields (e.g. 'meta') are passed through.
async function pack(obj) {
  const wire = { ...obj };
  if (wire.sdp) wire.sdp = compactSdp(wire.sdp);
  const json = JSON.stringify(wire);
  const cs = new Blob([json]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  const buf = new Uint8Array(await new Response(cs).arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function unpack(s) {
  s = s.trim().replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  const ds = new Blob([buf]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  const wire = JSON.parse(await new Response(ds).text());
  if (wire.sdp) wire.sdp = expandSdp(wire.sdp);
  return wire;
}

// ---------- ICE wait ----------
function waitIceComplete(pc) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve();
    const t = setTimeout(() => {
      log('ICE gather timeout, proceeding with partial candidates', 'warn');
      pc.removeEventListener('icegatheringstatechange', onChange);
      resolve();
    }, ICE_TIMEOUT);
    function onChange() {
      if (pc.iceGatheringState === 'complete') {
        clearTimeout(t);
        pc.removeEventListener('icegatheringstatechange', onChange);
        resolve();
      }
    }
    pc.addEventListener('icegatheringstatechange', onChange);
  });
}

// ---------- PeerConnection wiring ----------
function newPC() {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  pc.oniceconnectionstatechange = () => {
    log(`ICE: ${pc.iceConnectionState}`, pc.iceConnectionState === 'failed' ? 'err' : 'muted');
    if (pc.iceConnectionState === 'failed') {
      log('Direct P2P unavailable. STUN insufficient (symmetric NAT / CGNAT / strict firewall). No TURN fallback by design.', 'err');
    }
  };
  pc.onconnectionstatechange = () => log(`PC: ${pc.connectionState}`, 'muted');
  return pc;
}

// ---------- QR helper (qrcode-generator global `qrcode`) ----------
function renderQr(container, text) {
  container.innerHTML = '';
  // typeNumber 0 = auto-detect; EC level 'L' for shorter codes (text is large).
  try {
    const qr = qrcode(0, 'L');
    qr.addData(text);
    qr.make();
    container.innerHTML = qr.createImgTag(4, 8);
  } catch (e) {
    container.textContent = 'QR too large; use copy/paste.';
    log(`QR generation failed: ${e.message}`, 'warn');
  }
}

// ---------- Routing: sender vs receiver based on URL hash ----------
function route() {
  const params = new URLSearchParams(location.hash.slice(1));
  if (params.has('o')) {
    receiverView.hidden = false;
    initReceiver(params.get('o'));
  } else {
    senderView.hidden = false;
    initSender();
  }
}

// =================================================================
// SENDER
// =================================================================
function initSender() {
  const fileInput     = $('fileInput');
  const fileMeta      = $('fileMeta');
  const hashProgress  = $('hashProgress');
  const hashBar       = $('hashBar');
  const hashPct       = $('hashPct');
  const shareStep     = $('shareStep');
  const shareLink     = $('shareLink');
  const copyLink      = $('copyLink');
  const showQr        = $('showQr');
  const qrBox         = $('qrBox');
  const answerStep    = $('answerStep');
  const answerIn      = $('answerIn');
  const acceptAnswer  = $('acceptAnswer');
  const senderTrans   = $('senderTransfer');
  const senderStatus  = $('senderStatus');
  const sendBar       = $('sendBar');
  const sendStats     = $('sendStats');
  const filepick      = document.querySelector('.filepick');

  // Drag-n-drop
  ['dragenter', 'dragover'].forEach((ev) => filepick.addEventListener(ev, (e) => {
    e.preventDefault(); filepick.classList.add('drag');
  }));
  ['dragleave', 'drop'].forEach((ev) => filepick.addEventListener(ev, (e) => {
    e.preventDefault(); filepick.classList.remove('drag');
  }));
  filepick.addEventListener('drop', (e) => {
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      onFile(e.dataTransfer.files[0]);
    }
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) onFile(e.target.files[0]);
  });

  let pc, ctrl, ctrlQ, dataChans = [], file = null, meta = null;

  async function onFile(f) {
    file = f;
    meta = null;
    fileMeta.hidden = false;
    fileMeta.innerHTML = `<strong>${escapeHtml(f.name)}</strong> &middot; ${fmtBytes(f.size)} &middot; ${escapeHtml(f.type || 'application/octet-stream')}`;
    shareStep.hidden = true;
    answerStep.hidden = true;
    senderTrans.hidden = true;
    qrBox.hidden = true;

    log(`File selected: ${f.name} (${fmtBytes(f.size)})`);

    // 1. Stream hash file
    hashProgress.hidden = false;
    let hash;
    try {
      hash = await streamHash(f, (done, total) => {
        const pct = Math.floor((done / total) * 100);
        hashBar.value = pct;
        hashPct.textContent = `${pct}%`;
      });
    } catch (e) {
      log(`Hashing failed: ${e.message}`, 'err');
      return;
    }
    log(`SHA-256: ${hash}`, 'ok');
    hashProgress.hidden = true;

    const totalChunks = Math.ceil(f.size / CHUNK_SIZE);

    // 2. Create PC + channels + offer
    senderStatus.textContent = 'Setting up connection...';
    pc = newPC();
    ctrl = pc.createDataChannel('ctrl', { ordered: true });
    // Install the ctrl message queue immediately, so receiver's 'go' isn't lost
    // if it arrives before we attach a listener.
    ctrlQ = makeCtrlQueue(ctrl);
    dataChans = [];
    for (let i = 0; i < STREAMS; i++) {
      dataChans.push(pc.createDataChannel(`data-${i}`, { ordered: true }));
    }

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await waitIceComplete(pc);
    } catch (e) {
      log(`Offer creation failed: ${e.message}`, 'err');
      return;
    }

    meta = {
      name: f.name,
      size: f.size,
      mime: f.type || 'application/octet-stream',
      hash,
      chunkSize: CHUNK_SIZE,
      totalChunks,
      streams: STREAMS,
    };

    // 3. Pack offer + meta into URL hash
    let packed;
    try {
      packed = await pack({ sdp: pc.localDescription, meta });
    } catch (e) {
      log(`Pack failed: ${e.message}`, 'err');
      return;
    }
    const url = `${location.origin}${location.pathname}#o=${packed}`;
    shareLink.value = url;
    shareStep.hidden = false;
    answerStep.hidden = false;
    log(`Share link ready (${url.length} chars)`);

    copyLink.onclick = () => {
      navigator.clipboard.writeText(url).then(() => log('Link copied', 'ok'));
    };
    showQr.onclick = () => {
      qrBox.hidden = !qrBox.hidden;
      if (!qrBox.hidden) renderQr(qrBox, url);
    };
  }

  acceptAnswer.onclick = async () => {
    const text = answerIn.value.trim();
    if (!text) return log('Answer code empty', 'warn');
    let answer;
    try {
      answer = await unpack(text);
    } catch (e) {
      return log(`Bad answer code: ${e.message}`, 'err');
    }
    try {
      await pc.setRemoteDescription(answer.sdp);
      log('Answer accepted, waiting for channels to open...', 'ok');
    } catch (e) {
      return log(`setRemoteDescription failed: ${e.message}`, 'err');
    }
    acceptAnswer.disabled = true;
    answerIn.disabled = true;
    senderTrans.hidden = false;
    senderStatus.textContent = 'Waiting for channels to open...';

    await Promise.all([ctrl, ...dataChans].map(waitChanOpen));
    log('All channels open. Waiting for receiver to be ready...', 'ok');
    senderStatus.textContent = 'Waiting for receiver...';

    // Receiver signals readiness via 'go' on ctrl once its sink is opened.
    // Metadata is already in the URL — no need to re-send.
    await ctrlQ.wait((m) => m.type === 'go');
    log('Receiver ready, starting transfer', 'ok');
    senderStatus.textContent = 'Transferring...';

    try {
      await sendChunks(file, dataChans, (sent, total, speed) => {
        const pct = Math.floor((sent / total) * 100);
        sendBar.value = pct;
        sendStats.textContent = `${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%) @ ${speed}`;
      });
    } catch (e) {
      log(`Transfer failed: ${e.message}`, 'err');
      senderStatus.textContent = 'Failed';
      return;
    }

    ctrl.send(JSON.stringify({ type: 'done' }));
    senderStatus.textContent = 'Transfer complete';
    log('Transfer complete', 'ok');
  };
}

// =================================================================
// RECEIVER
// =================================================================
function initReceiver(packedOffer) {
  const recvMeta      = $('recvMeta');
  const downloadStep  = $('downloadStep');
  const startDownload = $('startDownload');
  const answerOutStep = $('answerOutStep');
  const answerOut     = $('answerOut');
  const copyAnswer    = $('copyAnswer');
  const showAnswerQr  = $('showAnswerQr');
  const answerQrBox   = $('answerQrBox');
  const recvTrans     = $('recvTransfer');
  const recvStatus    = $('recvStatus');
  const recvBar       = $('recvBar');
  const recvStats     = $('recvStats');
  const recvResult    = $('recvResult');

  let unpacked;
  unpack(packedOffer).then((u) => {
    unpacked = u;
    const m = u.meta;
    recvMeta.innerHTML =
      `<div><strong>${escapeHtml(m.name)}</strong></div>` +
      `<div>Size: ${fmtBytes(m.size)}</div>` +
      `<div>Type: ${escapeHtml(m.mime)}</div>` +
      `<div>SHA-256: ${m.hash}</div>` +
      `<div>Chunks: ${m.totalChunks} &times; ${fmtBytes(m.chunkSize)}</div>`;
    downloadStep.hidden = false;
    log(`Offer parsed: ${m.name} ${fmtBytes(m.size)}`);
  }).catch((e) => {
    recvMeta.innerHTML = `<span style="color:var(--err)">Bad offer link: ${escapeHtml(e.message)}</span>`;
    log(`Unpack offer failed: ${e.message}`, 'err');
  });

  startDownload.onclick = async () => {
    startDownload.disabled = true;
    const m = unpacked.meta;

    // Open the sink FIRST, while we still have user activation. The
    // answer-paste roundtrip can easily exceed the activation window
    // (~5s), so calling showSaveFilePicker later would be rejected.
    recvTrans.hidden = false;
    recvStatus.textContent = 'Choose where to save the file...';
    let sink;
    try {
      sink = await openSink(m);
    } catch (e) {
      log(`Sink open failed: ${e.message}`, 'err');
      startDownload.disabled = false;
      return;
    }
    log(`Receive sink: ${sink.type}`, 'muted');
    recvStatus.textContent = 'Negotiating connection...';

    const pc = newPC();
    const channels = {};
    let collected = 0;
    const expected = 1 + m.streams;

    const allReady = new Promise((resolve) => {
      pc.ondatachannel = (e) => {
        const ch = e.channel;
        channels[ch.label] = ch;
        collected++;
        log(`channel ${ch.label} received (${collected}/${expected})`, 'muted');
        if (collected === expected) resolve();
      };
    });

    try {
      await pc.setRemoteDescription(unpacked.sdp);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await waitIceComplete(pc);
    } catch (e) {
      return log(`Answer creation failed: ${e.message}`, 'err');
    }

    const packed = await pack({ sdp: pc.localDescription });
    answerOut.value = packed;
    answerOutStep.hidden = false;
    log(`Answer code ready (${packed.length} chars). Send it back to sender.`);
    recvStatus.textContent = 'Waiting for sender to paste your answer code...';

    copyAnswer.onclick = () => navigator.clipboard.writeText(packed).then(() => log('Answer copied', 'ok'));
    showAnswerQr.onclick = () => {
      answerQrBox.hidden = !answerQrBox.hidden;
      if (!answerQrBox.hidden) renderQr(answerQrBox, packed);
    };

    await allReady;
    const ctrl = channels['ctrl'];
    const dataChans = [];
    for (let i = 0; i < m.streams; i++) dataChans.push(channels[`data-${i}`]);

    await Promise.all([ctrl, ...dataChans].map(waitChanOpen));
    log('All channels open', 'ok');
    recvStatus.textContent = 'Receiving...';

    const ctrlQ = makeCtrlQueue(ctrl);

    let received = 0;
    const totalBytes = m.size;
    const start = performance.now();
    let lastUpdate = 0;
    let allDone;
    const allDoneP = new Promise((resolve) => { allDone = resolve; });

    for (const ch of dataChans) {
      ch.binaryType = 'arraybuffer';
      ch.onmessage = async (e) => {
        const buf = e.data;
        if (!(buf instanceof ArrayBuffer)) return;
        const view = new DataView(buf);
        const chunkId = view.getUint32(0, false);
        const payload = new Uint8Array(buf, HEADER_LEN);
        await sink.write(chunkId, payload);
        received += payload.byteLength;
        const now = performance.now();
        if (now - lastUpdate > 100 || received === totalBytes) {
          lastUpdate = now;
          const pct = Math.floor((received / totalBytes) * 100);
          recvBar.value = pct;
          recvStats.textContent = `${fmtBytes(received)} / ${fmtBytes(totalBytes)} (${pct}%) @ ${fmtSpeed(received, now - start)}`;
        }
        if (received === totalBytes) allDone();
      };
      ch.onclose = () => log(`channel ${ch.label} closed`, 'muted');
      ch.onerror = (e) => log(`channel ${ch.label} error: ${e.message || e}`, 'err');
    }

    // Subscribe to 'done' before signaling 'go' to avoid a race where sender
    // pushes all chunks + 'done' faster than this side attaches its waiter
    // (the queue catches it anyway, but be explicit).
    const donePromise = ctrlQ.wait((msg) => msg.type === 'done');
    ctrl.send(JSON.stringify({ type: 'go' }));
    log('Sent go, awaiting chunks...');

    // Wait for both: explicit done signal AND all bytes received. SCTP is
    // reliable+ordered per channel so this is belt-and-suspenders.
    await Promise.all([donePromise, allDoneP]);
    log('All chunks received', 'ok');

    // Finalize sink, verify hash
    recvStatus.textContent = 'Finalizing & verifying hash...';
    const result = await sink.finalize();
    log('Verifying SHA-256...');
    const localHash = await hashBlob(result.blob || result.file);
    if (localHash === m.hash) {
      log(`Hash OK: ${localHash}`, 'ok');
    } else {
      log(`HASH MISMATCH! expected ${m.hash} got ${localHash}`, 'err');
    }

    recvResult.hidden = false;
    if (result.url) {
      recvResult.innerHTML = `<a href="${result.url}" download="${escapeHtml(m.name)}">Download ${escapeHtml(m.name)}</a>`;
    } else {
      recvResult.textContent = `Saved to disk via File System Access API.`;
    }
    recvStatus.textContent = 'Done';
  };
}

// =================================================================
// File hashing — streaming via hash-wasm
// =================================================================
async function streamHash(file, onProgress) {
  const { createSHA256 } = window.hashwasm;
  const hasher = await createSHA256();
  hasher.init();
  let off = 0;
  while (off < file.size) {
    const end = Math.min(off + HASH_BLOCK, file.size);
    const buf = new Uint8Array(await file.slice(off, end).arrayBuffer());
    hasher.update(buf);
    off = end;
    if (onProgress) onProgress(off, file.size);
    // Yield to UI thread
    await new Promise((r) => setTimeout(r, 0));
  }
  return hasher.digest('hex');
}

async function hashBlob(blob) {
  const { createSHA256 } = window.hashwasm;
  const hasher = await createSHA256();
  hasher.init();
  let off = 0;
  while (off < blob.size) {
    const end = Math.min(off + HASH_BLOCK, blob.size);
    const buf = new Uint8Array(await blob.slice(off, end).arrayBuffer());
    hasher.update(buf);
    off = end;
    await new Promise((r) => setTimeout(r, 0));
  }
  return hasher.digest('hex');
}

// =================================================================
// Sender chunk pump — round-robin across N channels, with backpressure
// =================================================================
async function sendChunks(file, channels, onProgress) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  let sent = 0;
  const start = performance.now();
  let lastUpdate = 0;

  // Pre-configure low-water threshold once
  for (const ch of channels) ch.bufferedAmountLowThreshold = BUF_LOW;

  // Per-channel queue index — round-robin assignment chunkId % N
  // Each channel processes its own slice of chunkIds, sequentially.
  const perChan = channels.map((_, idx) => (async () => {
    for (let chunkId = idx; chunkId < totalChunks; chunkId += channels.length) {
      const ch = channels[idx];
      if (ch.readyState !== 'open') throw new Error(`channel ${ch.label} not open`);

      // Backpressure: pause if buffer too big.
      if (ch.bufferedAmount > BUF_HIGH) {
        await new Promise((resolve) => {
          const onLow = () => { ch.removeEventListener('bufferedamountlow', onLow); resolve(); };
          ch.addEventListener('bufferedamountlow', onLow);
        });
      }

      const offset = chunkId * CHUNK_SIZE;
      const end = Math.min(offset + CHUNK_SIZE, file.size);
      let payload;
      try {
        payload = new Uint8Array(await file.slice(offset, end).arrayBuffer());
      } catch (e) {
        throw new Error(`File read failed at chunk ${chunkId}: ${e.message} (file may have been moved or deleted)`);
      }

      const frame = new Uint8Array(HEADER_LEN + payload.length);
      new DataView(frame.buffer).setUint32(0, chunkId, false);
      frame.set(payload, HEADER_LEN);
      ch.send(frame);

      sent += payload.length;
      const now = performance.now();
      if (onProgress && (now - lastUpdate > 100 || sent === file.size)) {
        lastUpdate = now;
        onProgress(sent, file.size, fmtSpeed(sent, now - start));
      }
    }
  })());

  await Promise.all(perChan);
}

// =================================================================
// Receiver sink — File System Access API or Blob array fallback
// =================================================================
async function openSink(meta) {
  // Prefer File System Access API: supports seek -> good for multi-stream.
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: meta.name });
      const writable = await handle.createWritable({ keepExistingData: false });
      return {
        type: 'fsa',
        async write(chunkId, payload) {
          const offset = chunkId * meta.chunkSize;
          await writable.write({ type: 'write', position: offset, data: payload });
        },
        async finalize() {
          await writable.close();
          const file = await handle.getFile();
          return { file, url: null };
        },
      };
    } catch (e) {
      log(`showSaveFilePicker dismissed/failed: ${e.message}; falling back to in-memory.`, 'warn');
    }
  }

  // Fallback: keep all chunks in an array indexed by chunkId.
  const chunks = new Array(meta.totalChunks);
  return {
    type: 'memory',
    async write(chunkId, payload) {
      // Copy payload because the underlying ArrayBuffer may be reused.
      chunks[chunkId] = new Uint8Array(payload);
    },
    async finalize() {
      const blob = new Blob(chunks, { type: meta.mime });
      const url = URL.createObjectURL(blob);
      return { blob, url };
    },
  };
}

// =================================================================
// Channel helpers
// =================================================================
function waitChanOpen(ch) {
  return new Promise((resolve, reject) => {
    if (ch.readyState === 'open') return resolve();
    ch.addEventListener('open', () => resolve(), { once: true });
    ch.addEventListener('error', (e) => reject(new Error(`${ch.label} error: ${e.message || 'unknown'}`)), { once: true });
  });
}

// Attach a queue to a control channel so JSON messages are never lost to a
// missing listener. Returns { wait(predicate) -> Promise<msg> }.
//
// Why: sender's ctrl message handler (or vice-versa) might be attached AFTER
// the peer has already sent a message. Without a queue, that message would
// be dropped silently. The queue buffers messages and matches them against
// waiters as they arrive.
function makeCtrlQueue(ch) {
  const buf = [];
  const waiters = [];
  ch.addEventListener('message', (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    const idx = waiters.findIndex((w) => w.pred(msg));
    if (idx >= 0) {
      const w = waiters.splice(idx, 1)[0];
      w.resolve(msg);
    } else {
      buf.push(msg);
    }
  });
  return {
    wait(pred) {
      const idx = buf.findIndex(pred);
      if (idx >= 0) return Promise.resolve(buf.splice(idx, 1)[0]);
      return new Promise((resolve) => waiters.push({ pred, resolve }));
    },
  };
}

// =================================================================
// Utilities
// =================================================================
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// =================================================================
// Boot
// =================================================================
window.addEventListener('load', () => {
  if (!window.RTCPeerConnection) {
    log('WebRTC not supported in this browser.', 'err');
    return;
  }
  if (!window.hashwasm) {
    log('hash-wasm failed to load.', 'err');
    return;
  }
  if (typeof window.qrcode !== 'function') {
    log('qrcode-generator failed to load.', 'warn');
  }
  if (!window.CompressionStream) {
    log('CompressionStream not supported in this browser.', 'err');
    return;
  }
  route();
});
