# Cryptography Projects

Two Node.js projects for ICS 3201 Computer Security and Cryptography. Each one is self-contained
in its own folder.

| Folder | Project | Web UI |
|---|---|---|
| [`project1-password-manager`](project1-password-manager) | Secure password manager: PBKDF2, HMAC-keyed domains, padded AES-GCM records, swap and rollback defenses | http://localhost:3001 |
| [`project2-secure-messenger`](project2-secure-messenger) | End-to-end encrypted messenger using the Signal Double Ratchet with government key escrow, including out-of-order delivery | http://localhost:3002 |

## Getting started
```
cd project1-password-manager   # or project2-secure-messenger
npm install
npm test        # run the test suite
npm run ui      # start the demo web UI
```

Each project's README describes its design, and `SHORT_ANSWERS.md` answers the assignment's
short-answer questions.
