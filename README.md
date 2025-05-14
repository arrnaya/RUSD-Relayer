# 🛰️ TokenBridge Relayer

A production-grade, TypeScript-based **cross-chain relayer** for monitoring and executing `MessageSent` events across EVM-compatible blockchains using the `TokenBridge` smart contract. It automates message passing and ensures robust retry handling for failed transactions.

---

## 🚀 Features

- Listens to `MessageSent` events from source chains
- Calls `receiveMessage()` on destination chain's TokenBridge
- Validates contract state (`initialized`, `paused`, access control)
- Automatic gas estimation with 50% buffer
- Retry logic with exponential backoff
- Persistent failed message queue
- Duplicate message protection
- Fallback RPC handling for rate limits or timeouts
- Clean shutdown with listener teardown
- Supports multiple chains concurrently

---

## 🏗️ Project Structure

```

.
├── src/
│   ├── relayer.ts         # Main relayer logic
│   ├── config.ts          # TokenBridge configs and chains
│   ├── constants.ts       # Constants for logging and intervals
│   ├── logger.ts          # Winston logger setup
│   └── failedMessages.ts  # Persistent failed message handling
├── .env                   # API keys and private key
├── tsconfig.json
└── package.json

````

---

## ⚙️ Prerequisites

- Node.js v18+
- TypeScript
- Ethers v6
- dotenv

Install dependencies:

```bash
npm install
````

---

## 🔐 Environment Variables (`.env`)

```env
PRIVATE_KEY=your_private_key
INFURA_API_KEY=your_infura_key
ALCHEMY_API_KEY=your_alchemy_key
```

---

## 🧠 Configuration (`config.ts`)

Define supported chains and TokenBridge contract addresses:

```ts
export const SUPPORTED_CHAINS = {
  1: 'Ethereum Mainnet',
  137: 'Polygon',
  56: 'BSC',
  // Add more as needed
};

export const TOKEN_BRIDGE_ADDRESSES = {
  1: '0xYourTokenBridgeOnEthereum',
  137: '0xYourTokenBridgeOnPolygon',
  // ...
};
```

---

## 🪄 Usage

```bash
npm run build     # Compile TypeScript
npm start         # Run the relayer
```

---

## 🛠️ Commands

* `npm run build`: Compiles TypeScript to `dist/`
* `npm start`: Runs the compiled code

---

## 🧪 TODO / Roadmap

* [ ] Add Prometheus metrics & Grafana dashboards
* [ ] Redis-backed deduplication and concurrency control
* [ ] Dockerize and deploy via PM2 or systemd
* [ ] Health check endpoint

## 📄 License

MIT License — use freely, modify responsibly.

```
