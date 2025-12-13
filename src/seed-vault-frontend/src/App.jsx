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

function isValidPrincipal(text) {
  try {
    Principal.fromText(text);
    return true;
  } catch (_) {
    return false;
  }
}

function isValidAccountId(text) {
  return text.length === 64 && /^[0-9A-Fa-f]+$/.test(text);
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
  const [canisterCycles, setCanisterCycles] = useState(0);
  const [paymentPrompt, setPaymentPrompt] = useState(null);
  const [isAddingSeed, setIsAddingSeed] = useState(false);
  const [decryptingSeeds, setDecryptingSeeds] = useState({});
  const [deletingSeeds, setDeletingSeeds] = useState({});
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');
  const [estimatedCost, setEstimatedCost] = useState(null);
  const [isTransferOpen, setIsTransferOpen] = useState(false);
  const [recipient, setRecipient] = useState('');
  const [transferAmount, setTransferAmount] = useState('');

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
    setEstimatedCost(null);
    setIsTransferOpen(false);
    setRecipient('');
    setTransferAmount('');
  }

  async function loadAccount() {
    setIsRefreshing(true);
    try {
      const details = await backendActor.get_account_details();
      setAccountDetails(details);
      const cycles = await backendActor.canister_cycles();
      setCanisterCycles(Number(cycles));
      const deriveEstimate = await backendActor.estimate_cost('derive', 1);
      const totalE8s = Number(deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
      setEstimatedCost(formatIcp(totalE8s));
    } catch (error) {
      setStatus(`Unable to fetch account details: ${error.message}`);
      setEstimatedCost(null);
    } finally {
      setIsRefreshing(false);
    }
  }

  async function waitForBalance(required, message) {
    setPaymentPrompt({
      required,
      message,
    });

    setStatus('Awaiting payment...');

    let checks = 0;
    while (checks < 12) {
      const details = await backendActor.get_account_details();
      setAccountDetails(details);
      if (Number(details.balance) >= required) {
        setPaymentPrompt(null);
        setStatus('Payment received. Proceeding...');
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 5000));
      checks += 1;
    }
    setPaymentPrompt(null);
    setStatus('Payment timeout.');
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
    setDecryptingSeeds((prev) => ({ ...prev, [seedName]: true }));
    setStatus(`Preparing to decrypt "${seedName}"...`);
    try {
      const [decryptEstimate, deriveEstimate] = await Promise.all([
        backendActor.estimate_cost('decrypt', 1),
        backendActor.estimate_cost('derive', 1),
      ]);

      const required = Number(decryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
      const confirmed = window.confirm(
        `Decrypting "${seedName}" will cost ~${formatIcp(required)} ICP (including ledger fee and 5% buffer). Continue?`,
      );
      if (!confirmed) {
        setDecryptingSeeds((prev) => ({ ...prev, [seedName]: false }));
        setStatus('');
        return;
      }

      setLoading(true);
      setStatus(`Attempting payment for decryption of "${seedName}"...`);
      await waitForBalance(
        required,
        `Please transfer at least ${formatIcp(required)} ICP for decryption and key derivation.`,
      );
      setStatus(`Decrypting "${seedName}"...`);
      const transportSecretKey = TransportSecretKey.random();
      const result = await backendActor.get_seed_cipher_and_key(
        seedName,
        transportSecretKey.publicKeyBytes(),
      );
      if ('err' in result) {
        throw new Error(result.err);
      }
      const [cipher, iv, encryptedKeyBytes] = result.ok;

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

      const vetKeyBytes =
        vetKey instanceof Uint8Array
          ? vetKey
          : vetKey instanceof ArrayBuffer
            ? new Uint8Array(vetKey)
            : ArrayBuffer.isView(vetKey)
              ? new Uint8Array(vetKey.buffer, vetKey.byteOffset, vetKey.byteLength)
              : new Uint8Array(vetKey);
      const hashed = await crypto.subtle.digest('SHA-256', vetKeyBytes);
      const key = new Uint8Array(hashed);

      const phraseText = await decrypt(new Uint8Array(cipher), key, new Uint8Array(iv));
      setDecryptedSeeds((prev) => ({ ...prev, [seedName]: phraseText }));
      await loadAccount();

      backendActor.convert_collected_icp?.().catch(() => {});
      setStatus(`"${seedName}" decrypted successfully.`);
    } catch (error) {
      setStatus(`Failed to decrypt "${seedName}": ${error.message}`);
    } finally {
      setDecryptingSeeds((prev) => ({ ...prev, [seedName]: false }));
      setLoading(false);
    }
  }

  async function deleteSeed(seedName) {
    const confirmed = window.confirm(
      `Are you sure you want to delete "${seedName}"? This action cannot be undone.`,
    );
    if (!confirmed) return;

    setDeletingSeeds((prev) => ({ ...prev, [seedName]: true }));
    setLoading(true);
    setStatus(`Deleting "${seedName}"...`);
    try {
      const result = await backendActor.delete_seed(seedName);
      if ('err' in result) {
        throw new Error(result.err);
      }
      await loadSeeds();
      setDecryptedSeeds((prev) => {
        const updated = { ...prev };
        delete updated[seedName];
        return updated;
      });
      setStatus(`"${seedName}" deleted.`);
    } catch (error) {
      setStatus(`Failed to delete "${seedName}": ${error.message}`);
    } finally {
      setDeletingSeeds((prev) => ({ ...prev, [seedName]: false }));
      setLoading(false);
    }
  }

  async function handleAddSeed(event) {
    event.preventDefault();
    if (!name || !phrase) return;
    setIsAddingSeed(true);
    setStatus('Preparing to save seed...');
    try {
      const [encryptEstimate, deriveEstimate] = await Promise.all([
        backendActor.estimate_cost('encrypt', 1),
        backendActor.estimate_cost('derive', 1),
      ]);
      const required = Number(encryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
      const confirmed = window.confirm(
        `Saving "${name}" will cost ~${formatIcp(required)} ICP (including ledger fee and 5% buffer). Continue?`,
      );
      if (!confirmed) {
        setIsAddingSeed(false);
        setStatus('');
        return;
      }

      setStatus('Attempting payment for encryption...');
      setLoading(true);
      await waitForBalance(
        required,
        `Please transfer at least ${formatIcp(required)} ICP for encryption and key derivation.`,
      );
      setStatus(`Encrypting and saving "${name}"...`);
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
      await loadAccount();
      setStatus('Seed saved');

      backendActor.convert_collected_icp?.().catch(() => {});
    } catch (error) {
      setStatus(`Failed to save seed: ${error.message}`);
    } finally {
      setIsAddingSeed(false);
      setLoading(false);
    }
  }

  async function handleTransfer(event) {
    event.preventDefault();
    if (!recipient || !transferAmount) return;

    const amountNum = parseFloat(transferAmount);
    if (Number.isNaN(amountNum) || amountNum <= 0) {
      setStatus('Invalid amount');
      return;
    }

    const amountE8s = Math.floor(amountNum * 1e8);
    const upperRecipient = recipient.toUpperCase();
    const isAccountId = isValidAccountId(upperRecipient);
    const isPid = isValidPrincipal(recipient);

    if (!isAccountId && !isPid) {
      setStatus('Invalid recipient: must be a Principal ID or 64-hex account ID');
      return;
    }

    const feeMultiplier = isAccountId ? 2 : 1;
    const totalE8s = amountE8s + feeMultiplier * LEDGER_FEE_E8S;

    if (accountDetails && Number(accountDetails.balance) < totalE8s) {
      setStatus(`Insufficient balance: need at least ${formatIcp(totalE8s)} ICP (including fees)`);
      return;
    }

    const confirmed = window.confirm(
      `Transfer ${transferAmount} ICP to ${recipient}? Ledger fee: ${formatIcp(feeMultiplier * LEDGER_FEE_E8S)} ICP. Total deduction: ${formatIcp(totalE8s)} ICP.`,
    );
    if (!confirmed) return;

    setLoading(true);
    setStatus('Transferring...');
    try {
      const result = await backendActor.transfer_icp(recipient, amountE8s);
      if ('err' in result) {
        throw new Error(result.err);
      }
      setStatus(`Transfer successful. Block: ${result.ok}`);
      try {
        await navigator.clipboard.writeText(String(result.ok));
        setStatus(`Transfer successful. Block: ${result.ok} (copied)`);
      } catch (_) {
        // Clipboard access can fail in some browsers; ignore.
      }
      await loadAccount();
      setIsTransferOpen(false);
      setRecipient('');
      setTransferAmount('');
    } catch (error) {
      setStatus(`Transfer failed: ${error.message}`);
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
            {accountDetails ? (
              <>
                <div className="account-line">
                  <p>Deposit ICP to Account ID:</p>
                  <div className="account-id-container">
                    <strong className="account-id">
                      {computeAccountId(accountDetails.canister, accountDetails.subaccount)}
                    </strong>
                    <button
                      type="button"
                      className={`copy-button ${copyStatus === 'Copied!' ? 'copied' : ''}`}
                      onClick={async () => {
                        const id = computeAccountId(accountDetails.canister, accountDetails.subaccount);
                        await navigator.clipboard.writeText(id);
                        setCopyStatus('Copied!');
                        setTimeout(() => setCopyStatus(''), 2000);
                      }}
                    >
                      {copyStatus || 'Copy'}
                    </button>
                  </div>
                </div>
                <p>
                  Available balance for this app:{' '}
                  <strong>{formatIcp(accountDetails.balance)} ICP</strong>
                </p>
                <p>
                  Canister cycles: <strong>{canisterCycles.toLocaleString()}</strong>
                </p>
                <p className="muted">A 0.0001 ICP ledger fee is reserved for each charge.</p>
                <p className="muted">
                  Estimated cost per encrypt/decrypt: ~
                  {estimatedCost ? `${estimatedCost} ICP` : 'loading...'}
                </p>
                <p className="muted">
                  Pricing adjusts dynamically based on the current ICP/XDR exchange rate and may change
                  frequently.
                </p>
              </>
            ) : (
              <p className="muted">Loading account details...</p>
            )}
            <button onClick={loadAccount} disabled={isRefreshing || loading} className={isRefreshing ? 'button-loading' : ''}>
              Refresh balance & cycles
              {isRefreshing && <span className="loading-spinner" />}
            </button>
            {!isTransferOpen && (
              <button
                onClick={() => {
                  setIsTransferOpen(true);
                  loadAccount();
                }}
                disabled={loading}
              >
                Transfer
              </button>
            )}
            {paymentPrompt && (
              <div className="callout">
                <p>
                  {paymentPrompt.message || (
                    <>
                      Please transfer at least <strong>{formatIcp(paymentPrompt.required)} ICP</strong> to
                      the account above.
                    </>
                  )}
                </p>
                <p className="muted">Waiting for funds to arrive...</p>
              </div>
            )}
            {isTransferOpen && (
              <div className="callout">
                <h3>Transfer ICP</h3>
                <form onSubmit={handleTransfer}>
                  <label>
                    Recipient (Principal ID or 64-char Account ID)
                    <input
                      required
                      value={recipient}
                      onChange={(e) => setRecipient(e.target.value.trim())}
                      placeholder="aaaaa-aa or 64-hex account id"
                    />
                  </label>
                  <label>
                    Amount (ICP)
                    <input
                      required
                      type="number"
                      step="0.00000001"
                      min="0.00000001"
                      value={transferAmount}
                      onChange={(e) => setTransferAmount(e.target.value)}
                      placeholder="0.1"
                    />
                  </label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button type="submit" disabled={loading || !recipient || !transferAmount}>
                      Send
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setIsTransferOpen(false);
                        setRecipient('');
                        setTransferAmount('');
                        setStatus('');
                      }}
                      disabled={loading}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
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
              <button
                type="submit"
                disabled={!name || !phrase || isAddingSeed || loading}
                className={isAddingSeed ? 'button-loading' : ''}
              >
                Save encrypted seed
                {isAddingSeed && <span className="loading-spinner" />}
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
                      <div className="seed-actions">
                        {!decryptedSeeds[seedName] && (
                          <button
                            onClick={() => decryptSeed(seedName)}
                            disabled={decryptingSeeds[seedName] || loading || deletingSeeds[seedName]}
                            className={decryptingSeeds[seedName] ? 'button-loading' : ''}
                          >
                            Decrypt
                            {decryptingSeeds[seedName] && <span className="loading-spinner" />}
                          </button>
                        )}
                        <button
                          onClick={() => deleteSeed(seedName)}
                          disabled={decryptingSeeds[seedName] || deletingSeeds[seedName] || loading}
                          className={`delete-button ${deletingSeeds[seedName] ? 'button-loading' : ''}`}
                        >
                          Delete
                          {deletingSeeds[seedName] && <span className="loading-spinner" />}
                        </button>
                      </div>
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
