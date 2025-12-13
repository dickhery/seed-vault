# Seed Vault

Seed Vault is a secure decentralized application (dapp) built on the Internet Computer Protocol (ICP) blockchain. It allows users to encrypt and store seed phrases (e.g., mnemonic phrases for cryptocurrency wallets) online in a privacy-preserving and secure manner. By leveraging ICP's **vetKeys** (Verifiably Encrypted Threshold Keys) feature, Seed Vault ensures that seed phrases are encrypted using advanced cryptographic primitives, making it a safe alternative to traditional offline storage methods like paper or hardware wallets.

Unlike centralized storage solutions, Seed Vault uses ICP's distributed architecture to store encrypted data on-chain, while decryption keys are derived on-demand and only accessible to the authenticated user. This minimizes risks such as data breaches, as plaintext seed phrases are never stored or transmitted. The app is designed for users who need convenient access to their seed phrases without compromising security.

## Key Features
- **Secure Encryption and Storage**: Seed phrases are encrypted using AES-GCM with keys derived from vetKeys, ensuring confidentiality.
- **User-Controlled Decryption**: Users see a list of seed phrase titles upon authentication. Decryption is performed per seed phrase, only when explicitly requested.
- **Billing for Operations**: Users are billed in ICP (converted to cycles) for encryption/decryption to cover computation costs, promoting fair usage.
- **Internet Identity Authentication**: Seamless login using ICP's Internet Identity for secure, pseudonymous access.
- **On-Chain Storage**: Encrypted data is stored directly on the ICP blockchain, benefiting from its tamper-proof and replicated nature.

## How the App Works
1. **Authentication**: Users log in via Internet Identity (II), a secure, decentralized authentication system on ICP. This provides a Principal ID for user-specific data access without revealing personal information.

2. **Viewing Seed Titles**: After login, the app fetches and displays a list of saved seed phrase titles (e.g., "My Wallet Seed"). No decryption occurs here—only metadata is shown, keeping costs low and security high.

3. **Adding a Seed Phrase**:
   - Enter a title and the seed phrase.
   - The app prompts for confirmation, showing the estimated ICP cost (based on cycle consumption for key derivation and encryption).
   - Upon confirmation, the user transfers ICP to the canister's subaccount.
   - A symmetric key is derived using vetKeys (see Technical Details below).
   - The seed phrase is encrypted client-side using AES-GCM with a random IV (Initialization Vector).
   - The encrypted ciphertext and IV are stored on the canister under the user's Principal.

4. **Decrypting a Seed Phrase**:
   - Next to each title, there's a "Decrypt" button.
   - Clicking it shows a popup with the estimated ICP cost and requires confirmation.
   - After payment, the app retrieves the encrypted ciphertext and IV from the canister.
   - A fresh symmetric key is derived using vetKeys.
   - Decryption happens client-side in the browser, displaying the plaintext seed phrase temporarily.

5. **Billing and Cycles Management**:
   - Operations like key derivation (vetKD calls) and encryption/decryption consume cycles (ICP's computation unit).
   - The app estimates costs dynamically using exchange rates from ICP's Exchange Rate Canister (XRC).
   - Users deposit ICP to their subaccount on the canister, which converts it to cycles via the Cycles Minting Canister (CMC).
   - A small buffer covers ledger fees (0.0001 ICP per transfer).

6. **Transferring ICP**: Users can transfer unused ICP from their subaccount to another Principal or account ID.

## Technical Details: Encryption, Decryption, and Security
Seed Vault uses a combination of ICP's vetKeys and standard cryptographic primitives for robust security. Here's a breakdown:

### vetKeys Overview
- **What are vetKeys?**: vetKeys (Verifiably Encrypted Threshold Key Derivation) is a cryptographic protocol on ICP that derives keys from a distributed master key held across subnet nodes. It uses threshold cryptography (BLS12-381 curve) to ensure no single node can access or reconstruct keys. Keys are derived deterministically based on user input (e.g., seed name) and context (user Principal + domain separator).
- **Key Derivation Process**:
  - The backend canister calls ICP's vetKD API (`vetkd_derive_key`) with the user's Principal as context and seed name as input.
  - A transport key pair is generated client-side (Ed25519 or similar).
  - The derived key is encrypted under the transport public key and returned to the client.
  - Client verifies and decrypts it using the transport private key.
- **Why Secure?**: vetKeys are encrypted at all times during derivation and delivery. The master key is threshold-shared (requiring 2/3 subnet nodes to cooperate), preventing single-point failures or attacks. Derivations are verifiable, ensuring no tampering.

### Encryption/Decryption
- **Algorithm**: AES-GCM (256-bit key) for symmetric encryption.
  - Key: Derived from vetKeys via SHA-256 hash (ensuring 256-bit strength).
  - IV: 12-byte random value generated client-side.
  - Process:
    - Encryption: `ciphertext = AES-GCM.encrypt(plaintext, key, iv)`.
    - Decryption: `plaintext = AES-GCM.decrypt(ciphertext, key, iv)`.
- **Client-Side Operations**: All encryption/decryption happens in the browser using WebCrypto API, ensuring plaintext never leaves the user's device.
- **Storage**: Only ciphertext and IV are stored on-chain. The canister has no access to keys or plaintext.

### Security Benefits
- **Privacy**: vetKeys ensure unique keys per user/seed, with domain separation preventing cross-app collisions. ICP's pseudonymity (via II) hides real identities.
- **Tamper-Proof**: Data on ICP is replicated across nodes and tamper-evident.
- **No Persistent Keys**: Keys are derived on-demand, reducing exposure (no storage in localStorage or databases).
- **Resistance to Attacks**:
  - **Brute-Force**: AES-GCM is quantum-resistant with 256-bit keys.
  - **Subnet Compromise**: Threshold design tolerates up to 1/3 malicious nodes.
  - **Man-in-the-Middle**: vetKeys are encrypted and verifiable; II uses secure delegations.
  - **Data Leaks**: Encrypted storage means breaches reveal nothing useful.
- **Billing Security**: Payments use ICP ledger (ICRC-1) with subaccounts, preventing overcharges.
- **Limitations**: Relies on browser security and user caution (e.g., avoid phishing). Not a replacement for hardware wallets for high-value assets.

For more on vetKeys, see ICP's [vetKeys Documentation](https://internetcomputer.org/docs/current/developer-docs/integrations/vetkeys/) and the [Encrypted Notes Tutorial](https://internetcomputer.org/docs/current/samples/vetkeys-encrypted-notes).

## Getting Started

### Prerequisites
- Node.js (v16+)
- dfx (ICP SDK): Install via `sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"`
- Git

### Deploy Your Own Version
1. Clone the repository:
   ```
   gh repo clone dickhery/seed-vault
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
   - This deploys the backend and frontend canisters.
   - Note: Switch vetKD key to `"key_1"` in `src/seed-vault-backend/main.mo` for production (uses production master key).
   - Access the app at the frontend URL provided (e.g., `https://<frontend-canister-id>.icp0.io`).

### Running Locally
> **Canister Reuse Note**: dfx reuses canister IDs from `canister_ids.json`. Deploy with the same network flag to update existing canisters. Internet Identity (II) is not in `dfx.json`; deploy locally only for testing.

To test locally:
```
# Start the replica in the background
dfx start --clean --background

# (Optional) Deploy local Internet Identity for dev auth
dfx deploy internet_identity --argument '(null)'
export CANISTER_ID_INTERNET_IDENTITY=$(dfx canister id internet_identity)

# Deploy project canisters (backend + frontend)
dfx deploy
```

- App available at `http://localhost:4943?canisterId={asset_canister_id}`.
- For frontend changes: `npm start` (runs at `http://localhost:3000`, proxies API to replica).

Generate Candid interface after backend changes:
```
npm run generate
```

### vetKD Local Setup
- Uses management canister (`aaaaa-aa`) directly.
- Local key: `"dfx_test_key"` (in `main.mo`).
- For mainnet: Switch to `"test_key_1"` or `"key_1"` and attach cycles for vetKD calls.

### Internet Identity Usage
- **Mainnet/Production**: Frontend points to official II at `https://identity.ic0.app` (when `DFX_NETWORK=ic`).
- **Local**: Deploy local II (commands above) and set `CANISTER_ID_INTERNET_IDENTITY` for correct login URL.

### Note on Frontend Environment Variables
If hosting without dfx:
- Set `DFX_NETWORK=ic` in Webpack.
- Or override `process.env.DFX_NETWORK` in declarations.
- Or write a custom `createActor` constructor.

## Contributing
Fork the repo, make changes, and submit a PR. Ensure tests pass and ad script is in `index.html` (enforced by `check-ad-script.cjs`).

## License
This project is licensed under the MIT License.