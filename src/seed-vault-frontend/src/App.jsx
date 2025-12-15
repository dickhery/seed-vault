import { useEffect, useMemo, useRef, useState } from 'react';
import { AuthClient } from '@dfinity/auth-client';
import { Principal } from '@dfinity/principal';
import CryptoJS from 'crypto-js';
import { seed_vault_backend, createActor } from 'declarations/seed-vault-backend';
import { DerivedPublicKey, EncryptedVetKey, TransportSecretKey } from '@dfinity/vetkeys';

const II_URL = 'https://identity.ic0.app';
const LEDGER_FEE_E8S = 10_000;
const MAX_SEED_CHARS = 420;
const MAX_SEED_NAME_CHARS = 100;

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

function escapeHtml(unsafe = '') {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function toHex(bytes = []) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function wordArrayToUint8(wordArray) {
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const bytes = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i += 1) {
    bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return bytes;
}

function formatIcp(e8s) {
  return (Number(e8s) / 1e8).toFixed(6);
}

async function computeAccountId(canisterPrincipal, subaccountBytes) {
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

  let hashBytes;
  try {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      throw new Error('WebCrypto unavailable');
    }
    const hashBuffer = await crypto.subtle.digest('SHA-224', data);
    hashBytes = new Uint8Array(hashBuffer);
  } catch (error) {
    // Fallback for environments where SHA-224 is unsupported by WebCrypto.
    const hashWordArray = CryptoJS.SHA224(CryptoJS.lib.WordArray.create(data));
    hashBytes = wordArrayToUint8(hashWordArray);
  }
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

function crc32(bytes) {
  let checksum = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    checksum = CRC32_TABLE[(checksum ^ bytes[i]) & 0xff] ^ (checksum >>> 8);
  }
  return (checksum ^ 0xffffffff) >>> 0;
}

function hexToBytes(text) {
  if (text.length % 2 !== 0) return null;
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < text.length; i += 2) {
    const byte = parseInt(text.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) return null;
    bytes[i / 2] = byte;
  }
  return bytes;
}

function isValidAccountId(text) {
  if (text.length !== 64 || !/^[0-9A-Fa-f]+$/.test(text)) return false;
  const bytes = hexToBytes(text);
  if (!bytes || bytes.length !== 32) return false;
  const expected = crc32(bytes.subarray(4));
  const provided =
    (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  return (expected >>> 0) === (provided >>> 0);
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
  const [copyStatuses, setCopyStatuses] = useState({});
  const [isTransferOpen, setIsTransferOpen] = useState(false);
  const [recipient, setRecipient] = useState('');
  const [transferAmount, setTransferAmount] = useState('');
  const [hiddenSeeds, setHiddenSeeds] = useState({});
  const [estimateTimestamp, setEstimateTimestamp] = useState(null);
  const [isWaiting, setIsWaiting] = useState(false);
  const [usingFallbackPricing, setUsingFallbackPricing] = useState(false);
  const [accountId, setAccountId] = useState('');
  const waitingRef = useRef(false);
  const authClientRef = useRef(null);
  const [isSafari, setIsSafari] = useState(false);
  const [authReady, setAuthReady] = useState(false);

  const isSecureContext = useMemo(() => {
    if (typeof window === 'undefined') return true;
    if (window.isSecureContext) return true;
    const { protocol, hostname } = window.location;
    return protocol === 'https:' || hostname === 'localhost' || hostname === '127.0.0.1';
  }, []);

  useEffect(() => {
    if (typeof navigator !== 'undefined') {
      const ua = navigator.userAgent || '';
      setIsSafari(/safari/i.test(ua) && !/chrome|crios|android/i.test(ua));
    }

    AuthClient.create({ idleOptions: { disableIdle: true } })
      .then(async (client) => {
        authClientRef.current = client;
        setAuthReady(true);
        if (await client.isAuthenticated()) {
          setIdentity(client.getIdentity());
        }
      })
      .catch(() => {
        setStatus('Unable to initialize authentication. Please reload and try again.');
      });
  }, []);

  const backendActor = useMemo(() => {
    if (!identity) return seed_vault_backend;
    return createActor(process.env.CANISTER_ID_SEED_VAULT_BACKEND, {
      agentOptions: { identity },
    });
  }, [identity]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const { protocol, hostname, pathname, search, hash } = window.location;
    if (protocol !== 'https:' && hostname !== 'localhost') {
      window.location.href = `https://${hostname}${pathname}${search}${hash}`;
      return;
    }
    if (protocol !== 'https:') {
      setStatus('Warning: Use HTTPS for security.');
    }
  }, []);

  useEffect(() => {
    if (identity) {
      loadAccount();
      loadSeeds();
    }
  }, [identity, backendActor]);

  useEffect(() => {
    if (!accountDetails) {
      setAccountId('');
      return undefined;
    }

    let cancelled = false;
    (async () => {
      try {
        const id = await computeAccountId(accountDetails.canister, accountDetails.subaccount);
        if (!cancelled) {
          setAccountId(id);
        }
      } catch (_) {
        if (!cancelled) {
          setAccountId('');
          setStatus((prev) => prev || 'Unable to compute account ID.');
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [accountDetails]);

  useEffect(() => {
    if (!identity) return undefined;

    let timeoutId;
    const resetTimeout = () => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        logout();
        setStatus('Logged out after 30 minutes of inactivity for your security.');
      }, 1800000);
    };

    resetTimeout();
    window.addEventListener('mousemove', resetTimeout);
    window.addEventListener('keydown', resetTimeout);

    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener('mousemove', resetTimeout);
      window.removeEventListener('keydown', resetTimeout);
    };
  }, [identity]);

  async function login() {
    if (!isSecureContext) {
      setStatus('Login requires HTTPS or localhost to enable WebAuthn. Please reopen the app over HTTPS.');
      return;
    }

    const client = authClientRef.current || (await AuthClient.create({ idleOptions: { disableIdle: true } }));
    authClientRef.current = client;

    const loginOptions = {
      identityProvider: II_URL,
      onSuccess: async () => {
        const loggedInIdentity = client.getIdentity();
        setIdentity(loggedInIdentity);
        setStatus('');
      },
      onError: (err) => setStatus(`Login failed. ${err?.message || err}`),
      windowOpenerFeatures: isSafari ? '' : 'left=100,top=100,width=500,height=700',
    };

    // Safari (especially on mobile) is more permissive with full-page redirects than popups.
    if (isSafari) {
      loginOptions.maxTimeToLive = BigInt(24) * BigInt(60 * 60) * BigInt(1_000_000_000); // 24h in ns
    }

    await client.login(loginOptions);
  }

  async function logout() {
    if (!authClientRef.current) {
      authClientRef.current = await AuthClient.create({ idleOptions: { disableIdle: true } });
    }
    await authClientRef.current.logout();
    setIdentity(null);
    setSeedNames([]);
    setDecryptedSeeds({});
    setAccountDetails(null);
    setEstimatedCost(null);
    setEstimateTimestamp(null);
    setCopyStatus('');
    setCopyStatuses({});
    setIsTransferOpen(false);
    setRecipient('');
    setTransferAmount('');
  }

  useEffect(() => {
    if (Object.keys(decryptedSeeds).length === 0) return undefined;

    const timer = setTimeout(() => {
      setHiddenSeeds((prev) => {
        const updated = { ...prev };
        Object.keys(decryptedSeeds).forEach((seedName) => {
          updated[seedName] = true;
        });
        return updated;
      });
      setStatus('Seeds auto-hidden for security.');
    }, 300000);

    return () => clearTimeout(timer);
  }, [decryptedSeeds]);

  async function loadAccount() {
    setIsRefreshing(true);
    let hadError = false;
    try {
      try {
        const details = await backendActor.get_account_details();
        setAccountDetails(details);
      } catch (error) {
        console.error('get_account_details failed', error);
        hadError = true;
      }

      try {
        const cycles = await backendActor.canister_cycles();
        setCanisterCycles(Number(cycles));
      } catch (error) {
        console.error('canister_cycles failed', error);
        hadError = true;
      }

      try {
        const [encryptEstimate, decryptEstimate, deriveEstimate] = await Promise.all([
          backendActor.estimate_cost('encrypt', 1),
          backendActor.estimate_cost('decrypt', 1),
          backendActor.estimate_cost('derive', 1),
        ]);
        const fallback =
          encryptEstimate.fallback_used || decryptEstimate.fallback_used || deriveEstimate.fallback_used;
        const costE8s = Number(encryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
        setEstimatedCost(formatIcp(costE8s));

        let pricingSnapshot = null;
        try {
          pricingSnapshot = backendActor.pricing_status ? await backendActor.pricing_status() : null;
        } catch (error) {
          console.error('pricing_status failed', error);
          hadError = true;
        }

        const refreshedAt = pricingSnapshot?.last_refresh_nanoseconds
          ? Number(pricingSnapshot.last_refresh_nanoseconds / 1_000_000)
          : Date.now();
        setEstimateTimestamp(refreshedAt);
        const usedFallback = Boolean(fallback || pricingSnapshot?.fallback_used);
        setUsingFallbackPricing(usedFallback);
        if (usedFallback) {
          setStatus(
            'Using fallback pricing. Costs may shift once live rates are available—refresh before paying.',
          );
        }
      } catch (error) {
        console.error('estimate_cost failed', error);
        hadError = true;
      }

      if (hadError) {
        setStatus((prev) => prev || 'Some data may be stale. Please refresh to retry.');
      }
    } catch (error) {
      setStatus('Unable to fetch account details. Please try again.');
    } finally {
      setIsRefreshing(false);
    }
  }

  async function waitForBalance(required, message) {
    setIsWaiting(true);
    waitingRef.current = true;
    setPaymentPrompt({
      required,
      message,
    });

    setStatus('Awaiting payment...');

    let checks = 0;
    while (checks < 12 && waitingRef.current) {
      const details = await backendActor.get_account_details();
      setAccountDetails(details);
      if (Number(details.balance) >= required) {
        if (Number(details.balance) > required * 1.5) {
          setStatus('Overpayment detected. Excess will remain in your subaccount.');
        }
        setPaymentPrompt(null);
        setStatus('Payment received. Proceeding...');
        setIsWaiting(false);
        waitingRef.current = false;
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 5000));
      checks += 1;
    }
    setPaymentPrompt(null);
    setIsWaiting(false);
    const timeoutMessage = waitingRef.current
      ? 'Payment timeout.'
      : 'Payment cancelled by user.';
    waitingRef.current = false;
    setStatus(timeoutMessage);
    throw new Error(timeoutMessage);
  }

  async function hkdfExpand(keyBytes, info) {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(info));
    return new Uint8Array(signature);
  }

  async function deriveAesKeyVariantsFromVetKey(vetKeyBytes) {
    const hashed = new Uint8Array(await crypto.subtle.digest('SHA-256', vetKeyBytes));
    const expanded = await hkdfExpand(hashed, 'aes-256-gcm-seed-vault');
    const primary = expanded.subarray(0, 32);
    const legacy = hashed.subarray(0, 32);
    return { primary, legacy };
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

    const { primary } = await deriveAesKeyVariantsFromVetKey(vetKeyBytes);
    return primary;
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
      setHiddenSeeds((current) => {
        const retained = {};
        names.forEach((seedName) => {
          if (seedName in current) {
            retained[seedName] = current[seedName];
          }
        });
        return retained;
      });
    } catch (error) {
      setStatus('Failed to load seeds. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  async function decryptSeed(seedName) {
    setDecryptingSeeds((prev) => ({ ...prev, [seedName]: true }));
    setStatus(`Preparing to decrypt "${seedName}"...`);
    try {
      const [encryptEstimate, decryptEstimate, deriveEstimate] = await Promise.all([
        backendActor.estimate_cost('encrypt', 1),
        backendActor.estimate_cost('decrypt', 1),
        backendActor.estimate_cost('derive', 1),
      ]);
      const fallback =
        encryptEstimate.fallback_used || decryptEstimate.fallback_used || deriveEstimate.fallback_used;
      const required = Number(decryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
      const confirmed = window.confirm(
        `Decrypting "${seedName}" will cost ~${formatIcp(required)} ICP (including ledger fee and buffer).${
          fallback ? ' (Using fallback exchange rate estimate.)' : ''
        } Continue?\n\nWarning: Decrypt only on trusted devices. Seed will auto-hide after 5 minutes.`,
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
      const { primary, legacy } = await deriveAesKeyVariantsFromVetKey(vetKeyBytes);

      let phraseText;
      try {
        phraseText = await decrypt(new Uint8Array(cipher), primary, new Uint8Array(iv));
      } catch (primaryError) {
        // Attempt legacy direct-SHA key to allow older ciphertexts to decrypt.
        try {
          phraseText = await decrypt(new Uint8Array(cipher), legacy, new Uint8Array(iv));
          setStatus(
            `"${seedName}" decrypted with legacy key derivation. Please re-save to upgrade security.`,
          );
        } catch (_) {
          throw primaryError;
        }
      }
      setDecryptedSeeds((prev) => ({ ...prev, [seedName]: phraseText }));
      setHiddenSeeds((prev) => ({ ...prev, [seedName]: false }));
      await loadAccount();

      backendActor.convert_collected_icp?.().catch(() => {});
      setStatus(`"${seedName}" decrypted successfully.`);
    } catch (error) {
      setStatus(`Failed to decrypt "${seedName}". Please try again.`);
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
      setHiddenSeeds((prev) => {
        const updated = { ...prev };
        delete updated[seedName];
        return updated;
      });
      await loadAccount();
      setStatus(`"${seedName}" deleted.`);
    } catch (error) {
      setStatus(`Failed to delete "${seedName}". Please try again.`);
    } finally {
      setDeletingSeeds((prev) => ({ ...prev, [seedName]: false }));
      setLoading(false);
    }
  }

  async function handleAddSeed(event) {
    event.preventDefault();
    const trimmedName = name.trim();
    const trimmedPhrase = phrase.trim();
    const words = trimmedPhrase.split(/\s+/);
    if (!trimmedName || !trimmedPhrase) {
      setStatus('Seed name and phrase are required.');
      return;
    }
    if (trimmedName.length > MAX_SEED_NAME_CHARS) {
      setStatus(`Seed name is too long. Limit is ${MAX_SEED_NAME_CHARS} characters.`);
      return;
    }
    if (trimmedPhrase.length > MAX_SEED_CHARS) {
      setStatus(`Seed phrase is too long. Limit is ${MAX_SEED_CHARS} characters.`);
      return;
    }
    if (words.length < 12 || words.length > 24 || !words.every((word) => /^[a-z]+$/.test(word))) {
      setStatus('Seed phrase must be 12-24 lowercase words.');
      return;
    }
    setIsAddingSeed(true);
    setStatus('Preparing to save seed...');
    try {
      const securityConfirmed = window.confirm(
        'Warning: Enter and decrypt seed phrases only on trusted devices. Proceed to encrypt?',
      );
      if (!securityConfirmed) {
        setIsAddingSeed(false);
        setStatus('');
        return;
      }

      const [encryptEstimate, deriveEstimate] = await Promise.all([
        backendActor.estimate_cost('encrypt', 1),
        backendActor.estimate_cost('derive', 1),
      ]);
      const fallback = encryptEstimate.fallback_used || deriveEstimate.fallback_used;
      const required = Number(encryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
      const confirmed = window.confirm(
        `Saving "${trimmedName}" will cost ~${formatIcp(required)} ICP (including ledger fee and buffer).${
          fallback ? ' (Using fallback exchange rate estimate.)' : ''
        } Continue?`,
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
      setStatus(`Encrypting and saving "${trimmedName}"...`);
      const key = await deriveSymmetricKey(trimmedName);
      const { cipher, iv } = await encrypt(trimmedPhrase, key);
      const result = await backendActor.add_seed(trimmedName, cipher, iv);
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
      setStatus('Failed to save seed. Please try again.');
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
      setStatus('Transfer failed. Please try again.');
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
            <>
              {!isSecureContext && (
                <p className="status warning">
                  WebAuthn is blocked on insecure origins. Open the app via HTTPS or localhost, then try again.
                </p>
              )}
              <button onClick={login} disabled={!isSecureContext || !authReady}>
                Login with Internet Identity
              </button>
            </>
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
                      {accountId || 'Computing...'}
                    </strong>
                    <button
                      type="button"
                      className={`copy-button ${copyStatus === 'Copied!' ? 'copied' : ''}`}
                      onClick={async () => {
                        if (!isSecureContext) {
                          setStatus('Copy is only available over HTTPS or localhost.');
                          return;
                        }
                        if (!accountId) {
                          setStatus('Account ID is still computing. Please try again.');
                          return;
                        }
                        await navigator.clipboard.writeText(accountId);
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
                <details>
                  <summary>View pricing info</summary>
                  <div>
                      <p className="muted">A 0.0001 ICP ledger fee is reserved for each charge.</p>
                      <p className="muted">
                        Estimated cost per encrypt/decrypt: ~
                        {estimatedCost ? `${estimatedCost} ICP` : 'loading...'}
                      </p>
                    <p className="muted">
                      Last refreshed:{' '}
                      {estimateTimestamp
                        ? new Date(estimateTimestamp).toLocaleString()
                        : 'not yet updated'}
                    </p>
                    <p className="muted">
                      Pricing adjusts dynamically based on the current ICP/XDR exchange rate and may change
                      frequently.
                    </p>
                    {usingFallbackPricing && (
                      <p className="status warning">
                        Live exchange rate unavailable; showing the last known estimate. Use "Refresh balance &
                        cycles" to retry live pricing before paying.
                      </p>
                    )}
                  </div>
                </details>
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
                <button
                  type="button"
                  onClick={() => {
                    setIsWaiting(false);
                    waitingRef.current = false;
                    setPaymentPrompt(null);
                    setStatus('Payment cancelled by user.');
                  }}
                  disabled={!isWaiting}
                >
                  Cancel
                </button>
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
                  maxLength={MAX_SEED_NAME_CHARS}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Ledger wallet"
                />
                <p className="muted">{name.length}/{MAX_SEED_NAME_CHARS} characters</p>
                {name.length > MAX_SEED_NAME_CHARS && (
                  <p className="status error">Name exceeds {MAX_SEED_NAME_CHARS} characters.</p>
                )}
              </label>
              <label>
                Seed phrase
                <textarea
                  required
                  maxLength={MAX_SEED_CHARS}
                  value={phrase}
                  onChange={(e) => setPhrase(e.target.value)}
                  placeholder="twelve random words..."
                />
                <p className="muted">{phrase.length}/{MAX_SEED_CHARS} characters</p>
              </label>
                <button
                  type="submit"
                  disabled={!name || !phrase || name.length > MAX_SEED_NAME_CHARS || isAddingSeed || loading}
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
                        <p className="seed-name">{escapeHtml(seedName)}</p>
                        {decryptedSeeds[seedName] && (
                          <>
                            <p className="seed-phrase">
                              {hiddenSeeds[seedName] ? '••••••••••••••••••••••••••' : decryptedSeeds[seedName]}
                            </p>
                            <button
                              type="button"
                              className="hide-button"
                              onClick={() =>
                                setHiddenSeeds((prev) => ({ ...prev, [seedName]: !prev[seedName] }))
                              }
                            >
                              {hiddenSeeds[seedName] ? 'Show' : 'Hide'}
                            </button>
                            <button
                              type="button"
                              className={`copy-button ${copyStatuses[seedName] === 'Copied!' ? 'copied' : ''}`}
                              onClick={async () => {
                                if (hiddenSeeds[seedName]) {
                                  setStatus('Reveal the seed phrase before copying.');
                                  return;
                                }

                                if (!isSecureContext) {
                                  setStatus('Copy is only available over HTTPS or localhost.');
                                  return;
                                }

                                const confirmed = window.confirm(
                                  'Warning: Copying exposes the seed phrase to your clipboard. Continue?',
                                );
                                if (!confirmed) {
                                  setStatus('Copy cancelled.');
                                  return;
                                }

                                try {
                                  await navigator.clipboard.writeText(decryptedSeeds[seedName]);
                                  setCopyStatuses((prev) => ({ ...prev, [seedName]: 'Copied!' }));
                                  setTimeout(
                                    () => setCopyStatuses((prev) => ({ ...prev, [seedName]: '' })),
                                    2000,
                                  );
                                } catch (error) {
                                  setStatus('Failed to copy. Please try again.');
                                }
                              }}
                            >
                              {copyStatuses[seedName] || 'Copy'}
                            </button>
                          </>
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
