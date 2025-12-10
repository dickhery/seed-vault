import { useEffect, useMemo, useState } from 'react';
import { AuthClient } from '@dfinity/auth-client';
import { seed_vault_backend, createActor } from 'declarations/seed-vault-backend';
import { DerivedPublicKey, EncryptedVetKey, TransportSecretKey } from '@dfinity/vetkeys';

const II_URL = 'https://identity.ic0.app';
const LEDGER_FEE_E8S = 10_000;

function toHex(bytes = []) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatIcp(e8s) {
  return (Number(e8s) / 1e8).toFixed(6);
}

function App() {
  const [identity, setIdentity] = useState(null);
  const [seeds, setSeeds] = useState([]);
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
    setSeeds([]);
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
      const count = await backendActor.seed_count();
      if (Number(count) > 0) {
        await ensureFunds('decrypt', Number(count));
      }
      const result = await backendActor.get_my_seeds();
      if ('err' in result) {
        setStatus(result.err);
        return;
      }
      const decrypted = await Promise.all(
        result.ok.map(async ([seedName, cipher, iv]) => {
          const key = await deriveSymmetricKey(seedName);
          const phraseText = await decrypt(cipher, key, iv);
          return { name: seedName, phrase: phraseText };
        }),
      );
      setSeeds(decrypted);
    } catch (error) {
      setStatus(`Failed to load seeds: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleAddSeed(event) {
    event.preventDefault();
    setStatus('Encrypting and saving seed...');
    setLoading(true);
    try {
      await ensureFunds('encrypt', 1);
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
                  Deposit to canister <strong>{accountDetails.canister}</strong> using
                  subaccount <code>{toHex(accountDetails.subaccount)}</code>.
                </p>
                <p>
                  Available balance for this app:{' '}
                  <strong>{formatIcp(accountDetails.balance)} ICP</strong>
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
            ) : seeds.length === 0 ? (
              <p className="muted">No seeds stored yet.</p>
            ) : (
              <ul className="seed-list">
                {seeds.map((seed) => (
                  <li key={seed.name}>
                    <div>
                      <p className="seed-name">{seed.name}</p>
                      <p className="seed-phrase">{seed.phrase}</p>
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
