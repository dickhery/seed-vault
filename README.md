# Seed Vault

Seed Vault is a secure decentralized application (dapp) built on the Internet Computer Protocol (ICP) blockchain. It allows users to encrypt and store seed phrases (e.g., mnemonic phrases for cryptocurrency wallets) online in a privacy-preserving and secure manner. By leveraging ICP's **vetKeys** (Verifiably Encrypted Threshold Keys) feature, Seed Vault ensures that seed phrases are encrypted using advanced cryptographic primitives, making it a safe alternative to traditional offline storage methods like paper or hardware wallets.

Unlike centralized storage solutions, Seed Vault uses ICP's distributed architecture to store encrypted data on-chain, while decryption keys are derived on-demand and only accessible to the authenticated user. This minimizes risks such as data breaches, as plaintext seed phrases are never stored or transmitted. The app is designed for users who need convenient access to their seed phrases without compromising security.

## Table of Contents
- [Key Features](#key-features)
- [How the App Works](#how-the-app-works)
- [Technical Details: Encryption, Decryption, and Security](#technical-details-encryption-decryption-and-security)
- [Dynamic Pricing](#dynamic-pricing)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Deploy Your Own Version](#deploy-your-own-version)
  - [Running Locally](#running-locally)
  - [vetKD Local Setup](#vetkd-local-setup)
  - [Internet Identity Usage](#internet-identity-usage)
  - [Note on Frontend Environment Variables](#note-on-frontend-environment-variables)
- [Contributing](#contributing)
- [License](#license)

## Key Features
- **Secure Encryption and Storage**: Seed phrases are encrypted using AES-GCM with keys derived from vetKeys, ensuring confidentiality.
- **User-Controlled Decryption**: Users see a list of seed phrase titles upon authentication. Decryption is performed per seed phrase, only when explicitly requested.
- **Billing for Operations**: Users are billed in ICP (converted to cycles) for encryption/decryption to cover computation costs, promoting fair usage. Pricing is dynamic based on exchange rates.
- **Internet Identity Authentication**: Seamless login using ICP's Internet Identity for secure, pseudonymous access. Sessions auto-close after 10 minutes of inactivity for security.
- **On-Chain Storage**: Encrypted data is stored directly on the ICP blockchain, benefiting from its tamper-proof and replicated nature.
- **Idle Session Management**: Auth sessions close automatically after 10 minutes of inactivity to enhance security.

## How the App Works
1. **Authentication**: Users log in via Internet Identity (II), a secure, decentralized authentication system on ICP. This provides a Principal ID for user-specific data access without revealing personal information. Sessions expire after 10 minutes of inactivity (no mouse/keyboard/touch input).

2. **Viewing Seed Titles**: After login, the app fetches and displays a list of saved seed phrase titles (e.g., "My Wallet Seed"). No decryption occurs here—only metadata is shown, keeping costs low and security high.

3. **Adding a Seed Phrase**:
   - Enter a title and the seed phrase.
   - The app prompts for confirmation, showing the estimated ICP cost (based on dynamic cycle consumption for key derivation and encryption, fetched from exchange rates).
   - Upon confirmation, the user transfers ICP to the canister's subaccount.
   - A symmetric key is derived using vetKeys (see Technical Details below).
   - The seed phrase is encrypted client-side using AES-GCM with a random IV (Initialization Vector).
   - The encrypted ciphertext and IV are stored on the canister under the user's Principal.

4. **Decrypting a Seed Phrase**:
   - Next to each title, there's a "Decrypt" button.
   - Clicking it shows a popup with the estimated ICP cost and requires confirmation.
   - After payment, the app retrieves the encrypted ciphertext and IV from the canister.
   - A fresh symmetric key is derived using vetKeys.
   - Decryption happens client-side in the browser, displaying the plaintext seed phrase temporarily. The phrase auto-hides after 5 minutes for security.

5. **Billing and Cycles Management**:
   - Operations like key derivation (vetKD calls) and encryption/decryption consume cycles (ICP's computation unit).
   - The app estimates costs dynamically using exchange rates from ICP's Exchange Rate Canister (XRC), with fallbacks if XRC is unavailable.
   - Users deposit ICP to their subaccount on the canister, which converts it to cycles via the Cycles Minting Canister (CMC).
   - A small buffer covers ledger fees (0.0001 ICP per transfer).

6. **Transferring ICP**: Users can transfer unused ICP from their subaccount to another Principal or account ID.

## Technical Details: Encryption, Decryption, and Security
Seed Vault uses a combination of ICP's vetKeys and standard cryptographic primitives for robust security. Here's a simple explanation for non-technical users, followed by details.

### Simple Explanation of Security
Imagine your seed phrase is a secret message. Instead of storing it openly (risky!), Seed Vault "locks" it with a super-strong digital lock (encryption). The key to this lock is created on-the-fly using vetKeys, a special ICP feature that spreads the key-making process across many computers (nodes) so no single one can steal or fake it. Only you (after confirming payment) can get the key to unlock your message, and everything happens in your browser—nothing sensitive leaves your device. Even if someone hacks the app's storage, they get gibberish without your key.

### vetKeys Overview
- **What are vetKeys?**: vetKeys (Verifiably Encrypted Threshold Key Derivation) is like a team of trusted guards (ICP subnet nodes) who together create a unique key for your data. No single guard has the full key—they must collaborate (threshold cryptography on BLS12-381 curve), and the key is encrypted during creation. It's deterministic: Same inputs = same key, but unique per user/seed.
- **Why Secure?**: Keys are derived distributedly (no central weak point), encrypted at all times, and verifiable (you can check no tampering). ICP tolerates up to 1/3 bad nodes without compromise.
- **Key Derivation Process**:
  - Backend calls ICP's vetKD API (`vetkd_derive_key`) with your Principal as context and seed name as input.
  - Client generates a temporary "transport" key pair.
  - Derived key is encrypted under your transport public key and sent back.
  - Client verifies and decrypts it.
- For more, see [vetKeys Documentation](https://internetcomputer.org/docs/current/developer-docs/integrations/vetkeys/) and [How vetKeys Work](https://internetcomputer.org/docs/references/vetkeys-overview).

### Encryption/Decryption
- **Algorithm**: AES-GCM (256-bit key) for symmetric encryption—industry-standard, fast, and secure.
  - Key: Derived from vetKeys via SHA-256 hash (256-bit strength).
  - IV: 12-byte random value (prevents reuse attacks).
  - Process:
    - Encryption: Lock the phrase with key + IV.
    - Decryption: Unlock with same key + IV.
- **Client-Side Operations**: All locking/unlocking in your browser (WebCrypto API)—plaintext never hits servers.
- **Storage**: Only locked data (ciphertext) and IV stored on-chain. Canister can't access keys or plaintext.

### Security Benefits
- **Privacy**: Unique keys per user/seed; domain separation prevents mix-ups. II hides real identities.
- **Tamper-Proof**: ICP data replicated and immutable.
- **No Persistent Keys**: Keys derived fresh, no storage risks.
- **Resistance to Attacks**:
  - **Brute-Force**: AES-GCM quantum-resistant with huge keys.
  - **Hacks**: Threshold stops subnet takeovers; encrypted storage useless to thieves.
  - **Man-in-the-Middle**: vetKeys verifiable; II secure.
  - **Idle Risks**: Auto-logout after 10 min inactivity.
- **Limitations**: Browser security matters (use trusted devices, avoid phishing). Not for ultra-high-value assets—pair with hardware wallets.

For a similar app tutorial, see [Encrypted Notes Tutorial](https://internetcomputer.org/docs/tutorials/developer-liftoff/level-5/5.1-vetKeys-tutorial).

## Dynamic Pricing
Pricing ensures the backend canister always has cycles for operations. It's "dynamic" because ICP costs adjust with market exchange rates (ICP/XDR from XRC canister).

- **How It Works**: Cycle costs (e.g., vetKD derivation ~600M cycles) are fixed, but ICP equivalent varies. Backend fetches live rates every 5 min (fallback if unavailable, retry every 1 min). Frontend shows estimates with buffers (~5% + fees) and warns on fallbacks.
- **Why Dynamic?**: Protects against rate fluctuations—e.g., if ICP value drops, costs rise to maintain cycles.
- **User Impact**: See estimates before confirming. Overpayments stay in your subaccount. Canister auto-converts collected ICP to cycles.
- **Fallbacks**: If XRC fails (rare), uses last known/cached rate. Refresh to retry live pricing.

## Getting Started

### Prerequisites
- Node.js (v16+)
- dfx (ICP SDK): Install via `sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"`
- Git
- ICP wallet/account for funding deployments

### Deploy Your Own Version
If you want to run your own instance (e.g., for customization or privacy):
1. Clone the repository:
   ```
   git clone https://github.com/dickhery/seed-vault
   cd seed-vault
   ```
2. Install dependencies:
   ```
   npm install
   ```
3. Deploy to ICP mainnet:
   ```
   dfx deploy --network ic
   ```
   - This deploys backend and frontend canisters.
   - Note: In `src/seed-vault-backend/main.mo`, switch vetKD key to `"key_1"` for production (uses production master key). Use `"test_key_1"` for cheaper testing.
   - Access the app at `https://<frontend-canister-id>.icp0.io` (from dfx output).

### Running Locally
> **Note**: dfx reuses canister IDs from `canister_ids.json`. Deploy with the same network flag to update.

1. Start the replica:
   ```
   dfx start --clean --background
   ```
2. (Optional) Deploy local Internet Identity:
   ```
   dfx deploy internet_identity --argument '(null)'
   export CANISTER_ID_INTERNET_IDENTITY=$(dfx canister id internet_identity)
   ```
3. Deploy canisters:
   ```
   dfx deploy
   ```
- App at `http://localhost:4943?canisterId={asset_canister_id}`.
- For frontend dev: `npm start` (http://localhost:3000, proxies to replica).

Generate Candid after backend changes:
```
npm run generate
```

### vetKD Local Setup
- Uses management canister (`aaaaa-aa`) directly.
- Local key: `"dfx_test_key"` (in `main.mo`).
- For mainnet: Switch to `"test_key_1"` or `"key_1"` and attach cycles for vetKD calls.

### Internet Identity Usage
- **Mainnet**: Frontend uses official II at `https://identity.ic0.app` (when `DFX_NETWORK=ic`).
- **Local**: Deploy local II and set `CANISTER_ID_INTERNET_IDENTITY`.

### Note on Frontend Environment Variables
If hosting without dfx:
- Set `DFX_NETWORK=ic` in Webpack.
- Override `process.env.DFX_NETWORK` in declarations.
- Or customize `createActor`.

## Contributing
Fork, change, PR. Ensure tests pass and ad script in `index.html` (checked by `check-ad-script.cjs`).

## License
MIT License.