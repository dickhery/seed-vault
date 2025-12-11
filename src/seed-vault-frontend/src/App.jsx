import { useEffect, useMemo, useState } from 'react';
import { AuthClient } from '@dfinity/auth-client';
import { Principal } from '@dfinity/principal';
import CryptoJS from 'crypto-js';
import { seed_vault_backend, createActor } from 'declarations/seed-vault-backend';
import { DerivedPublicKey, EncryptedVetKey, TransportSecretKey } from '@dfinity/vetkeys';

const II_URL = 'https://identity.ic0.app';
const LEDGER_FEE_E8S = 10_000;

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function toHex(bytes = []) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatIcp(e8s) {
  return (Number(e8s) / 1e8).toFixed(6);
}

function wordArrayToUint8Array(wordArray) {
  const { words, sigBytes } = wordArray;
  const result = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i += 1) {
    const word = words[i >>> 2];
    result[i] = (word >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return result;
}

function computeAccountId(canisterPrincipal, subaccountBytes) {
  const owner = Principal.fromText(canisterPrincipal);
  const ownerBytes = owner.toUint8Array();
  const sub = new Uint8Array(32);
  if (subaccountBytes) {
    const provided = new Uint8Array(subaccountBytes);
    sub.set(provided.subarray(0, Math.min(provided.length, 32)));
  }

  const domainBuffer = new TextEncoder().encode('account-id');
  const data = new Uint8Array(1 + domainBuffer.length + ownerBytes.length + sub.length);
  data[0] = 0x0a;
  data.set(domainBuffer, 1);
  data.set(ownerBytes, 1 + domainBuffer.length);
  data.set(sub, 1 + domainBuffer.length + ownerBytes.length);

  const hash = CryptoJS.SHA224(CryptoJS.lib.WordArray.create(data));
  const hashBytes = wordArrayToUint8Array(hash);
  let checksum = 0xffffffff;
  for (let i = 0; i < hashBytes.length; i += 1) {
    checksum = CRC32_TABLE[(checksum ^ hashBytes[i]) & 0xff] ^ (checksum >>> 8);
  }
  checksum ^= 0xffffffff;
  const checksumBytes = new Uint8Array([
    (checksum >>> 24) & 0xff,
    (checksum >>> 16) & 0xff,
    (checksum >>> 8) & 0xff,
    checksum & 0xff,
  ]);

  const accountId = new Uint8Array(4 + hashBytes.length);
  accountId.set(checksumBytes);
  accountId.set(hashBytes, 4);

  return toHex(accountId).toUpperCase();
}

function App() {
  const [identity, setIdentity] = useState(null);
  const [seedNames, setSeedNames] = useState([]);
  const [decryptedSeeds, setDecryptedSeeds] = useState({});
  const [name, setName] = useState('');
  const [phrase, setPhrase] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const [accountDetails, setAccountDetails] = useState(null);
  const [paymentPrompt, setPaymentPrompt] = useState(null);

  const backendActor = useMemo(() => {
    if (!identity) return seed_vault_backend;
    return createActor(process.env.CANISTER_ID_SEED_VAULT_BACKEND, {
      agentOptions: { identity },
    });
  }, [identity]);

  useEffect(() => {
    if (identity) {
      loadAccount();
      loadSeeds();
    }
  }, [identity, backendActor]);

  async function login() {
    const authClient = await AuthClient.create();
    await authClient.login({
      identityProvider: II_URL,
      onSuccess: async () => {
        const loggedInIdentity = authClient.getIdentity();
        setIdentity(loggedInIdentity);
      },
    });
  }

  async function logout() {
    const authClient = await AuthClient.create();
    await authClient.logout();
    setIdentity(null);
    setSeedNames([]);
    setDecryptedSeeds({});
    setAccountDetails(null);
  }

  async function loadAccount() {
    try {
      const details = await backendActor.get_account_details();
      setAccountDetails(details);
    } catch (error) {
      setStatus(`Unable to fetch account details: ${error.message}`);
    }
  }

  async function ensureFunds(operation, count) {
    const { icp_e8s } = await backendActor.estimate_cost(operation, count);
    const required = Number(icp_e8s) + LEDGER_FEE_E8S;
    setPaymentPrompt({
      operation,
      required,
    });

    let checks = 0;
    while (checks < 12) {
      const details = await backendActor.get_account_details();
      setAccountDetails(details);
      if (Number(details.balance) >= required) {
        setPaymentPrompt(null);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 5000));
      checks += 1;
    }
    setPaymentPrompt(null);
    throw new Error('Insufficient funds to cover cycle costs.');
  }

  async function deriveSymmetricKey(seedName) {
    const transportSecretKey = TransportSecretKey.random();
    let encryptedKeyBytes;
    try {
      encryptedKeyBytes = await backendActor.encrypted_symmetric_key_for_seed(
        seedName,
        transportSecretKey.publicKeyBytes(),
      );
    } catch (error) {
      throw new Error(`vetKD derivation failed: ${error.message}`);
    }
    const encryptedVetKey = EncryptedVetKey.deserialize(new Uint8Array(encryptedKeyBytes));
    const derivedPublicKeyBytes = await backendActor.public_key();
    const derivedPublicKey = DerivedPublicKey.deserialize(new Uint8Array(derivedPublicKeyBytes));
    const input = new TextEncoder().encode(seedName);
    let vetKey;
    try {
      vetKey = encryptedVetKey.decryptAndVerify(transportSecretKey, derivedPublicKey, input);
    } catch (error) {
      throw new Error(`vetKD decryption failed: ${error.message}`);
    }

    // Ensure the value passed to WebCrypto is an ArrayBufferView/ArrayBuffer.
    const vetKeyBytes =
      vetKey instanceof Uint8Array
        ? vetKey
        : vetKey instanceof ArrayBuffer
          ? new Uint8Array(vetKey)
          : ArrayBuffer.isView(vetKey)
            ? new Uint8Array(vetKey.buffer, vetKey.byteOffset, vetKey.byteLength)
            : new Uint8Array(vetKey);

    const hashed = await crypto.subtle.digest('SHA-256', vetKeyBytes);
    return new Uint8Array(hashed);
  }

  async function encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const encoded = new TextEncoder().encode(plaintext);
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);
    return { cipher: new Uint8Array(cipher), iv };
  }

  async function decrypt(cipher, key, iv) {
    const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher);
    return new TextDecoder().decode(new Uint8Array(plaintext));
  }

  async function loadSeeds() {
    setLoading(true);
    try {
      const names = await backendActor.get_seed_names();
      setSeedNames(names);
      setDecryptedSeeds((current) => {
        const retained = {};
        names.forEach((seedName) => {
          if (current[seedName]) {
            retained[seedName] = current[seedName];
          }
        });
        return retained;
      });
    } catch (error) {
      setStatus(`Failed to load seeds: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function decryptSeed(seedName) {
    try {
      const [decryptEstimate, deriveEstimate] = await Promise.all([
        backendActor.estimate_cost('decrypt', 1),
        backendActor.estimate_cost('derive', 1),
      ]);

      const required = Number(decryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + 2 * LEDGER_FEE_E8S;
      const confirmed = window.confirm(
        `Decrypting "${seedName}" will cost ${formatIcp(required)} ICP (including ledger fees). Continue?`,
      );
      if (!confirmed) {
        return;
      }

      setLoading(true);
      await ensureFunds('decrypt', 1);
      await ensureFunds('derive', 1);
      const result = await backendActor.get_seed_cipher(seedName);
      if ('err' in result) {
        throw new Error(result.err);
      }
      const [cipher, iv] = result.ok;
      const key = await deriveSymmetricKey(seedName);
      const phraseText = await decrypt(cipher, key, iv);
      setDecryptedSeeds((prev) => ({ ...prev, [seedName]: phraseText }));
    } catch (error) {
      setStatus(`Failed to decrypt "${seedName}": ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleAddSeed(event) {
    event.preventDefault();
    if (!name || !phrase) return;
    try {
      const [encryptEstimate, deriveEstimate] = await Promise.all([
        backendActor.estimate_cost('encrypt', 1),
        backendActor.estimate_cost('derive', 1),
      ]);
      const required = Number(encryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + 2 * LEDGER_FEE_E8S;
      const confirmed = window.confirm(
        `Saving "${name}" will cost ${formatIcp(required)} ICP (including ledger fees). Continue?`,
      );
      if (!confirmed) {
        return;
      }

      setStatus('Encrypting and saving seed...');
      setLoading(true);
      await ensureFunds('encrypt', 1);
      await ensureFunds('derive', 1);
      const key = await deriveSymmetricKey(name);
      const { cipher, iv } = await encrypt(phrase, key);
      const result = await backendActor.add_seed(name, cipher, iv);
      if ('err' in result) {
        setStatus(result.err);
        return;
      }
      setName('');
      setPhrase('');
      await loadSeeds();
      setStatus('Seed saved');
    } catch (error) {
      setStatus(`Failed to save seed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app">
      <header>
        <div>
          <h1>Seed Vault</h1>
          <p>Store and decrypt your seed phrases securely with vetKeys and AES-GCM.</p>
        </div>
        <div className="auth">
          {identity ? (
            <>
              <span className="tag">Logged in</span>
              <button onClick={logout}>Logout</button>
            </>
          ) : (
            <button onClick={login}>Login with Internet Identity</button>
          )}
        </div>
      </header>

      {identity ? (
        <div className="content">
          <section className="card">
            <h2>Billing & Funding</h2>
            <p>
              Your principal: <strong>{identity.getPrincipal().toText()}</strong>
            </p>
            {accountDetails ? (
              <>
                <p>
                  Deposit ICP to Account ID:{' '}
                  <strong>{computeAccountId(accountDetails.canister, accountDetails.subaccount)}</strong>
                </p>
                <p>
                  Available balance for this app:{' '}
                  <strong>{formatIcp(accountDetails.balance)} ICP</strong>
                </p>
                <p className="muted">
                  (Canister: {accountDetails.canister} · Subaccount:{' '}
                  <code>{toHex(accountDetails.subaccount)}</code>)
                </p>
              </>
            ) : (
              <p className="muted">Loading account details...</p>
            )}
            <p className="muted">A 0.0001 ICP ledger fee is reserved for each charge.</p>
            {paymentPrompt && (
              <div className="callout">
                <p>
                  Please transfer at least <strong>{formatIcp(paymentPrompt.required)} ICP</strong> to
                  the account above to pay for {paymentPrompt.operation} costs.
                </p>
                <p className="muted">Waiting for funds to arrive...</p>
              </div>
            )}
          </section>

          <section className="card">
            <h2>Add a seed phrase</h2>
            <form onSubmit={handleAddSeed}>
              <label>
                Seed name
                <input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Ledger wallet"
                />
              </label>
              <label>
                Seed phrase
                <textarea
                  required
                  value={phrase}
                  onChange={(e) => setPhrase(e.target.value)}
                  placeholder="twelve random words..."
                />
              </label>
              <button type="submit" disabled={!name || !phrase || loading}>
                Save encrypted seed
              </button>
            </form>
            {status && <p className="status">{status}</p>}
          </section>

          <section className="card">
            <h2>Your seeds</h2>
            {loading ? (
              <p className="muted">Loading...</p>
            ) : seedNames.length === 0 ? (
              <p className="muted">No seeds stored yet.</p>
            ) : (
              <ul className="seed-list">
                {seedNames.map((seedName) => (
                  <li key={seedName}>
                    <div className="seed-row">
                      <div>
                        <p className="seed-name">{seedName}</p>
                        {decryptedSeeds[seedName] && (
                          <p className="seed-phrase">{decryptedSeeds[seedName]}</p>
                        )}
                      </div>
                      {!decryptedSeeds[seedName] && (
                        <button onClick={() => decryptSeed(seedName)} disabled={loading}>
                          Decrypt
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      ) : (
        <section className="card callout">
          <h2>Welcome</h2>
          <p>Authenticate with Internet Identity to view and add encrypted seed phrases.</p>
        </section>
      )}
    </main>
  );
}

export default App;
