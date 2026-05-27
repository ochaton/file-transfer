# P2P File Transfer

Minimal static WebRTC P2P file transfer. Pure HTML/CSS/JS, no build step. Deployable to GitHub Pages.

**Direct P2P only.** STUN for NAT discovery (`stun.cloudflare.com:3478`). No TURN, no relay, no server proxies your file traffic.

## Features

- Stream-hash SHA-256 of the source file on the sender (incremental, low RAM).
- 1 control + 4 data `RTCDataChannel`s — chunks sent round-robin in parallel.
- 64 KiB chunks with `bufferedAmount` backpressure (high/low watermarks).
- File never fully held in RAM on sender — chunks read from disk on-demand via `File.slice().arrayBuffer()`.
- Receiver streams to disk via **File System Access API** (`showSaveFilePicker`) when available — supports out-of-order writes via `position`. Falls back to in-memory `Blob[]` array when API is not supported (Firefox, Safari).
- SDP + metadata packed via `deflate-raw` + base64url into URL hash, so the sender produces one shareable link containing offer + file metadata.
- Answer code shown in textarea and as a QR code; receiver pastes it back to sender to complete the handshake.
- Clear error messages on ICE failure (no TURN fallback by design).

## How to use

### Sender

1. Open the page.
2. Drop or pick a file. SHA-256 is computed as the file is read.
3. Copy the share link (or scan the QR).
4. Send the link to the receiver out-of-band (chat, email, in person).
5. Wait — receiver will send back an answer code.
6. Paste the answer code into the textarea, click **Accept answer**.
7. Transfer starts. Watch the progress bar.

### Receiver

1. Open the share link the sender gave you. The page shows file metadata.
2. Click **Start download**.
3. Choose where to save the file (if your browser supports it).
4. Copy the answer code (or scan the QR) and send it back to the sender.
5. Once the sender pastes it, transfer starts.
6. After completion, SHA-256 is verified against the sender's hash.

## Limitations

- **Symmetric NAT / CGNAT / strict firewall**: connection will fail. The app surfaces the error explicitly. STUN alone is not sufficient in those environments — by design, no TURN fallback is offered.
- **No automatic signaling**: manual paste of the answer code back to the sender is required, since GitHub Pages cannot host a signaling endpoint.
- **In-memory fallback**: on browsers without `showSaveFilePicker` (Firefox, Safari), the entire file is reassembled in memory on the receiver. Practical limit: a few GiB depending on free RAM.
- **Hash on sender**: source `File` handle must remain valid throughout the transfer (do not move/delete the file). The browser re-reads slices from disk on demand.

## Deployment to GitHub Pages

1. Push this repo to GitHub.
2. Repository **Settings** → **Pages** → Source = `Deploy from a branch`, Branch = `main` (root).
3. Done. The `.nojekyll` file disables Jekyll so the `lib/` folder is served as-is.

## Local development

```sh
python3 -m http.server 8000
```

Then open `http://localhost:8000/` in two browser windows. `localhost` is a secure context so WebRTC works without HTTPS.

## File overview

```
index.html      — UI markup, two views (sender / receiver) selected by URL hash
style.css       — minimal dark theme
app.js          — all logic; heavily commented; entry point routes on `#o=...`
lib/
  hash-wasm.min.js  — streaming SHA-256 (WebAssembly), vendored
  qrcode.min.js     — QR code generator (qrcode-generator npm pkg), vendored
.nojekyll       — disables Jekyll on GitHub Pages
```

## Wire protocol

File metadata (`name`, `size`, `mime`, `hash`, `chunkSize`, `totalChunks`, `streams`) is bundled together with the offer SDP in the URL hash — no on-channel meta retransmission required.

Control channel (`ctrl`) — JSON strings:

| Direction | Message | When |
|---|---|---|
| receiver → sender | `{type:"go"}` | After receiver opens its sink and attaches data-channel listeners. Sender starts pushing chunks. |
| sender → receiver | `{type:"done"}` | After last chunk has been sent. Receiver finalizes the sink and verifies SHA-256. |

Data channels (`data-0` … `data-3`) — binary frames:

```
+--------------+-----------------------+
| chunkId (4B) | payload (≤ chunkSize) |
+--------------+-----------------------+
```

`chunkId` is `uint32` big-endian. Receiver writes payload at offset `chunkId * chunkSize`.

## License

MIT.
