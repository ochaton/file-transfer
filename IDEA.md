Create a minimal static WebRTC P2P file transfer web app deployable to GitHub Pages.

Requirements:
- Pure HTML + CSS + vanilla JavaScript.
- No build step.
- Files:
  - index.html
  - style.css
  - app.js
  - .nojekyll
  - README.md
- Use WebRTC DataChannel for file transfer.
- Use STUN only:
  - stun:stun.cloudflare.com:3478
- Do NOT use TURN.
- Do NOT proxy file traffic through any server.
- App must support manual signaling first:
  - User A creates offer.
  - User B pastes offer and creates answer.
  - User A pastes answer.
  - ICE candidates should be included in the SDP by waiting for ICE gathering to complete before showing offer/answer.
- UI:
  - Two modes: “Create room” and “Join room”.
  - Textareas for offer/answer copy-paste.
  - File picker.
  - Send file button.
  - Progress indicator.
  - Log panel.
- File transfer:
  - Split file into chunks, e.g. 64 KiB.
  - Use DataChannel bufferedAmount backpressure.
  - Send metadata first: filename, size, mime type.
  - Receiver reconstructs Blob and shows download link.
  - Calculate SHA-256 hash on sender and receiver if feasible.
- Handle errors clearly:
  - ICE failed.
  - DataChannel closed.
  - Direct P2P unavailable.
- Add comments explaining the WebRTC flow.
- Make it easy to deploy to GitHub Pages.
- Keep code simple, readable, and self-contained.

Important:
This is a STUN-only direct P2P app. If direct connectivity fails due to symmetric NAT, CGNAT, or strict firewall, the app should show a clear message and must not fall back to relay/proxy.
