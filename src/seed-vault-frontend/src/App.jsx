import { useEffect, useMemo, useRef, useState } from 'react';
import DOMPurify from 'dompurify';
import { AuthClient } from '@dfinity/auth-client';
import { Principal } from '@dfinity/principal';
import CryptoJS from 'crypto-js';
import { seed_vault_backend, createActor } from 'declarations/seed-vault-backend';
import { DerivedPublicKey, EncryptedVetKey, TransportSecretKey } from '@dfinity/vetkeys';

const II_URL = 'https://identity.ic0.app';
const LEDGER_FEE_E8S = 10_000;
const MAX_SEED_CHARS = 420;
const MAX_SEED_NAME_CHARS = 100;
const SEED_NAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9 _-]*[A-Za-z0-9])?$/u;
const SEED_TTL_MS = 5 * 60 * 1000;
const SANITIZE_OPTS = { ALLOWED_TAGS: [], ALLOWED_ATTR: [] };
const DERIVE_CYCLE_COST = 26_153_846_153;
const ENCRYPT_CYCLE_COST = 0;
const DECRYPT_CYCLE_COST = 0;
const BUFFER_PERCENT = 105;
const ICP_TO_CYCLES_BUFFER_E8S = LEDGER_FEE_E8S;
const FALLBACK_RATE = 1_000_000_000;

DOMPurify.setConfig(SANITIZE_OPTS);

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

function wordArrayToUint8(wordArray) {
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const bytes = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i += 1) {
    bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return bytes;
}

function bytesToBase64(bytes) {
  if (!bytes) return '';
  const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  const chunkSize = 1024;
  for (let i = 0; i < uint8.length; i += chunkSize) {
    const chunk = uint8.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function formatIcp(e8s) {
  return (Number(e8s) / 1e8).toFixed(6);
}

function costForOperationCycles(operation, count) {
  if (operation === 'encrypt') return ENCRYPT_CYCLE_COST * count;
  if (operation === 'decrypt') return DECRYPT_CYCLE_COST * count;
  if (operation === 'derive') return DERIVE_CYCLE_COST * count;
  return 0;
}

function estimateCostFromRate(operation, count, rate) {
  const cycles = costForOperationCycles(operation, count);
  if (cycles === 0) {
    return { icp_e8s: 0, fallback_used: false };
  }

  const safeRate = rate || FALLBACK_RATE;
  const numerator = cycles * 100_000;
  const baseCost = numerator / safeRate;
  const buffered = (baseCost * BUFFER_PERCENT) / 100;
  return {
    icp_e8s: Math.ceil(buffered) + ICP_TO_CYCLES_BUFFER_E8S,
    fallback_used: safeRate === FALLBACK_RATE,
  };
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

function validateSeedNameClient(rawName) {
  const normalized = rawName.trim();
  if (!normalized) {
    return { ok: false, error: 'Seed name is required.' };
  }
  if (normalized.length > MAX_SEED_NAME_CHARS) {
    return { ok: false, error: `Seed name is too long. Limit is ${MAX_SEED_NAME_CHARS} characters.` };
  }
  if (!SEED_NAME_PATTERN.test(normalized)) {
    return {
      ok: false,
      error: 'Seed name can only include letters, numbers, spaces, hyphens, and underscores, and cannot start or end with hyphens/underscores.',
    };
  }
  return { ok: true, value: normalized };
}

function validateSeedPhraseClient(rawPhrase) {
  const trimmed = rawPhrase.trim();
  if (!trimmed) {
    return { ok: false, error: 'Seed phrase is required.' };
  }
  if (trimmed.length > MAX_SEED_CHARS) {
    return { ok: false, error: `Seed phrase is too long. Limit is ${MAX_SEED_CHARS} characters.` };
  }
  if (/[<>]/.test(trimmed)) {
    return { ok: false, error: 'Angle brackets and HTML-like content are not allowed.' };
  }
  const words = trimmed.split(/\s+/u).filter(Boolean);
  if (words.length < 4) {
    return { ok: false, error: 'Seed phrase appears too short. Please double-check before saving.' };
  }
  return { ok: true, value: trimmed };
}

function getPrincipalText(identity) {
  try {
    return identity?.getPrincipal?.().toText() || '';
  } catch (_) {
    return '';
  }
}

function seedStorageKey(principalText, seedName) {
  return `seed_${principalText}_${seedName}`;
}

function sanitizeForHtml(text) {
  return DOMPurify.sanitize(text, SANITIZE_OPTS);
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
  const [seedExpirations, setSeedExpirations] = useState({});
  const [nowTs, setNowTs] = useState(Date.now());
  const [hasImages, setHasImages] = useState({});
  const [decryptedImages, setDecryptedImages] = useState({});
  const [imageFile, setImageFile] = useState(null);
  const [enlargedImage, setEnlargedImage] = useState(null);
  const [imagePreviewName, setImagePreviewName] = useState('');
  const [addingImageFor, setAddingImageFor] = useState(null);
  const [pendingImageFile, setPendingImageFile] = useState(null);
  const [encryptedSnapshots, setEncryptedSnapshots] = useState({});
  const [showEncrypted, setShowEncrypted] = useState({});
  const waitingRef = useRef(false);
  const authClientRef = useRef(null);
  const [isSafari, setIsSafari] = useState(false);
  const [authReady, setAuthReady] = useState(false);
  const seedClearTimeouts = useRef({});

  async function estimateCost(operation, count) {
    if (!backendActor) {
      throw new Error('Backend is not initialized yet. Please re-authenticate.');
    }
    const payloadCount = BigInt(count);
    try {
      if (backendActor.estimate_cost_v2) {
        return await backendActor.estimate_cost_v2({ operation, count: payloadCount });
      }
      return await backendActor.estimate_cost(operation, payloadCount);
    } catch (error) {
      console.error(`estimateCost(${operation}) failed`, error);
      const pricingSnapshot = backendActor.pricing_status
        ? await backendActor.pricing_status().catch(() => null)
        : null;
      const rateSnapshot = pricingSnapshot?.last_rate;
      const rate = typeof rateSnapshot === 'bigint' ? Number(rateSnapshot) : Number(rateSnapshot || 0);
      const derived = estimateCostFromRate(operation, count, rate || FALLBACK_RATE);
      return {
        cycles: BigInt(costForOperationCycles(operation, count)),
        icp_e8s: BigInt(derived.icp_e8s),
        fallback_used: true,
      };
    }
  }

  const decryptingAny = useMemo(
    () => Object.values(decryptingSeeds).some(Boolean),
    [decryptingSeeds],
  );
  const showProcessingNotice = loading && (isAddingSeed || decryptingAny);

  const principalText = useMemo(() => getPrincipalText(identity), [identity]);

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
    if (typeof window === 'undefined' || !principalText) {
      Object.values(seedClearTimeouts.current).forEach((timeoutId) => clearTimeout(timeoutId));
      seedClearTimeouts.current = {};
      setDecryptedSeeds({});
      setSeedExpirations({});
      setHiddenSeeds({});
      return;
    }

    const restored = {};
    const expirations = {};
    const hidden = {};
    const prefix = `seed_${principalText}_`;
    const now = Date.now();

    Object.values(seedClearTimeouts.current).forEach((timeoutId) => clearTimeout(timeoutId));
    seedClearTimeouts.current = {};

    for (let i = 0; i < window.sessionStorage.length; i += 1) {
      const key = window.sessionStorage.key(i);
      if (!key || !key.startsWith(prefix)) continue;
      const seedName = key.substring(prefix.length);
      try {
        const parsed = JSON.parse(window.sessionStorage.getItem(key));
        if (parsed?.expiresAt && parsed?.value && parsed.expiresAt > now) {
          restored[seedName] = parsed.value;
          expirations[seedName] = parsed.expiresAt;
          hidden[seedName] = true;
          const remaining = parsed.expiresAt - now;
          seedClearTimeouts.current[seedName] = setTimeout(() => clearDecryptedSeed(seedName), remaining);
        } else {
          window.sessionStorage.removeItem(key);
        }
      } catch (_) {
        window.sessionStorage.removeItem(key);
      }
    }

    setDecryptedSeeds(restored);
    setSeedExpirations(expirations);
    setHiddenSeeds(hidden);
  }, [principalText]);

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
        setStatus('Logged out after 10 minutes of inactivity for your security.');
      }, 600000);
    };

    resetTimeout();
    window.addEventListener('mousemove', resetTimeout);
    window.addEventListener('keydown', resetTimeout);
    window.addEventListener('touchstart', resetTimeout);

    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener('mousemove', resetTimeout);
      window.removeEventListener('keydown', resetTimeout);
      window.removeEventListener('touchstart', resetTimeout);
    };
  }, [identity]);

  useEffect(() => {
    if (!identity || !principalText) return undefined;

    const interval = setInterval(() => {
      const now = Date.now();
      setNowTs(now);
      const expired = [];
      setSeedExpirations((prev) => {
        const next = { ...prev };
        Object.entries(prev).forEach(([seedName, expiresAt]) => {
          if (expiresAt <= now) {
            expired.push(seedName);
            delete next[seedName];
          }
        });
        return next;
      });

      if (expired.length > 0) {
        expired.forEach((name) => clearDecryptedSeed(name));
        setStatus((prev) => prev || 'Decrypted seeds cleared automatically for safety.');
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [identity, principalText]);

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
      maxTimeToLive: BigInt(15) * BigInt(60) * BigInt(1_000_000_000), // 15 minutes in ns
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
    if (typeof window !== 'undefined' && principalText) {
      const prefix = `seed_${principalText}_`;
      for (let i = window.sessionStorage.length - 1; i >= 0; i -= 1) {
        const key = window.sessionStorage.key(i);
        if (key && key.startsWith(prefix)) {
          window.sessionStorage.removeItem(key);
        }
      }
    }
    Object.values(seedClearTimeouts.current).forEach((timeoutId) => clearTimeout(timeoutId));
    seedClearTimeouts.current = {};
    setIdentity(null);
    setSeedNames([]);
    setDecryptedSeeds({});
    setDecryptedImages({});
    setSeedExpirations({});
    setHasImages({});
    setEncryptedSnapshots({});
    setShowEncrypted({});
    setAddingImageFor(null);
    setPendingImageFile(null);
    setAccountDetails(null);
    setEstimatedCost(null);
    setEstimateTimestamp(null);
    setCopyStatus('');
    setCopyStatuses({});
    setIsTransferOpen(false);
    setRecipient('');
    setTransferAmount('');
  }

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
        let pricingSnapshot = null;
        try {
          pricingSnapshot = backendActor.pricing_status ? await backendActor.pricing_status() : null;
        } catch (error) {
          console.error('pricing_status failed', error);
          hadError = true;
        }

        const rateRaw = pricingSnapshot?.last_rate;
        let rate = typeof rateRaw === 'bigint' ? Number(rateRaw) : Number(rateRaw || 0);
        if (!rate) {
          rate = FALLBACK_RATE;
        }

        const encryptEstimate = estimateCostFromRate('encrypt', 1, rate);
        const deriveEstimate = estimateCostFromRate('derive', 1, rate);
        const fallback =
          pricingSnapshot?.fallback_used || encryptEstimate.fallback_used || deriveEstimate.fallback_used;
        const costE8s = Number(encryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
        setEstimatedCost(formatIcp(costE8s));

        const refreshedAtNs = pricingSnapshot?.last_refresh_nanoseconds;
        let refreshedAt = Date.now();
        if (typeof refreshedAtNs === 'bigint') {
          refreshedAt = Number(refreshedAtNs / 1_000_000n);
        } else if (typeof refreshedAtNs === 'number') {
          refreshedAt = Math.floor(refreshedAtNs / 1_000_000);
        } else if (refreshedAtNs !== undefined && refreshedAtNs !== null) {
          refreshedAt = Number(refreshedAtNs) / 1_000_000;
        }
        setEstimateTimestamp(refreshedAt);
        setUsingFallbackPricing(Boolean(fallback));
        if (fallback) {
          let fallbackReason = '';
          try {
            fallbackReason = await backendActor.get_last_xrc_error();
          } catch (error) {
            console.error('get_last_xrc_error failed', error);
          }

          const baseMessage =
            'Using fallback pricing. Costs may shift once live rates are available—refresh before paying.';
          const reasonSuffix = fallbackReason ? ` Reason: ${fallbackReason}` : '';
          setStatus(`${baseMessage}${reasonSuffix}`);
        }
      } catch (error) {
        console.error('estimate_cost failed', error);
        hadError = true;
        const fallbackEstimate = estimateCostFromRate('derive', 1, FALLBACK_RATE);
        const costE8s = fallbackEstimate.icp_e8s + LEDGER_FEE_E8S;
        setEstimatedCost(formatIcp(costE8s));
        setEstimateTimestamp(Date.now());
        setUsingFallbackPricing(true);
        setStatus((prev) => prev || 'Pricing unavailable; using fallback estimate.');
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
    const encoded =
      typeof plaintext === 'string'
        ? new TextEncoder().encode(plaintext)
        : plaintext instanceof Uint8Array
          ? plaintext
          : new Uint8Array(plaintext);
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);
    return { cipher: new Uint8Array(cipher), iv };
  }

  async function decrypt(cipher, key, iv) {
    const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher);
    return new TextDecoder().decode(new Uint8Array(plaintext));
  }

  async function decryptBytes(cipher, key, iv) {
    const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher);
    return new Uint8Array(plaintext);
  }

  async function loadSeeds() {
    setLoading(true);
    try {
      const names = await backendActor.get_seed_names();
      const normalized = names.map((entry) => entry.name || entry);
      const imageMap = names.reduce((acc, entry) => {
        const key = entry.name || entry;
        acc[key] = Boolean(entry.has_image);
        return acc;
      }, {});
      setHasImages(imageMap);
      setSeedNames(normalized);
      setDecryptedSeeds((current) => {
        const retained = {};
        normalized.forEach((seedName) => {
          if (current[seedName]) {
            retained[seedName] = current[seedName];
          }
        });
        return retained;
      });
      setHiddenSeeds((current) => {
        const retained = {};
        normalized.forEach((seedName) => {
          if (seedName in current) {
            retained[seedName] = current[seedName];
          }
        });
        return retained;
      });
      setDecryptedImages((current) => {
        const retained = {};
        normalized.forEach((seedName) => {
          if (current[seedName]) {
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

  function persistDecryptedSeed(seedName, phraseText) {
    if (typeof window === 'undefined' || !principalText || !window.sessionStorage) return;
    const expiresAt = Date.now() + SEED_TTL_MS;
    const payload = { value: phraseText, expiresAt };
    window.sessionStorage.setItem(seedStorageKey(principalText, seedName), JSON.stringify(payload));
    setDecryptedSeeds((prev) => ({ ...prev, [seedName]: phraseText }));
    setHiddenSeeds((prev) => ({ ...prev, [seedName]: true }));
    setSeedExpirations((prev) => ({ ...prev, [seedName]: expiresAt }));
    if (seedClearTimeouts.current[seedName]) {
      clearTimeout(seedClearTimeouts.current[seedName]);
    }
    seedClearTimeouts.current[seedName] = setTimeout(() => clearDecryptedSeed(seedName), SEED_TTL_MS);
  }

  function clearDecryptedSeed(seedName) {
    if (typeof window !== 'undefined' && principalText) {
      window.sessionStorage.removeItem(seedStorageKey(principalText, seedName));
    }
    if (seedClearTimeouts.current[seedName]) {
      clearTimeout(seedClearTimeouts.current[seedName]);
      delete seedClearTimeouts.current[seedName];
    }
    setDecryptedSeeds((prev) => {
      const next = { ...prev };
      delete next[seedName];
      return next;
    });
    setDecryptedImages((prev) => {
      const next = { ...prev };
      if (next[seedName]) {
        try {
          URL.revokeObjectURL(next[seedName]);
        } catch (_) {
          // Ignore revoke failures (e.g., URL already revoked)
        }
        delete next[seedName];
      }
      return next;
    });
    setSeedExpirations((prev) => {
      const next = { ...prev };
      delete next[seedName];
      return next;
    });
    setHiddenSeeds((prev) => {
      const next = { ...prev };
      delete next[seedName];
      return next;
    });
    setCopyStatuses((prev) => {
      const next = { ...prev };
      delete next[seedName];
      return next;
    });
  }

  async function decryptAllForSeed(seedName) {
    const validation = validateSeedNameClient(seedName);
    if (!validation.ok) {
      setStatus(validation.error);
      return;
    }
    const normalizedName = validation.value;
    if (!principalText) {
      setStatus('Identity is not ready yet. Please re-authenticate.');
      return;
    }
    setDecryptingSeeds((prev) => ({ ...prev, [seedName]: true }));
    setStatus(`Preparing to decrypt "${normalizedName}"...`);
    try {
      const hasImage = hasImages[normalizedName];
      const decryptOps = hasImage ? 2 : 1;
      const [decryptEstimate, deriveEstimate] = await Promise.all([
        estimateCost('decrypt', decryptOps),
        estimateCost('derive', 1),
      ]);
      const fallback = decryptEstimate.fallback_used || deriveEstimate.fallback_used;
      const required = Number(decryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
      const imageMention = hasImage ? ' and attached image' : '';
      const confirmed = window.confirm(
        `Decrypting "${normalizedName}"${imageMention} will cost ~${formatIcp(required)} ICP (including ledger fee and buffer).${
          fallback ? ' (Using fallback exchange rate estimate.)' : ''
        } Continue?\n\nWarning: Decrypt only on trusted devices. Seed data will Auto-encrypt and clear after 5 minutes.`,
      );
      if (!confirmed) {
        setDecryptingSeeds((prev) => ({ ...prev, [seedName]: false }));
        setStatus('');
        return;
      }

      setLoading(true);
      setStatus(`Attempting payment for decryption of "${normalizedName}"${imageMention}...`);
      await waitForBalance(
        required,
        `Please transfer at least ${formatIcp(required)} ICP for decryption${hasImage ? ' (seed and image)' : ''} and key derivation.`,
      );
      setStatus(`Decrypting "${seedName}"${imageMention}...`);
      const transportSecretKey = TransportSecretKey.random();
      const result = await backendActor.get_ciphers_and_key(
        normalizedName,
        transportSecretKey.publicKeyBytes(),
      );
      if ('err' in result) {
        throw new Error(result.err);
      }
      const [seedCipher, seedIv, imageCipherOpt, imageIvOpt, encryptedKeyBytes] = result.ok;

      const encryptedVetKey = EncryptedVetKey.deserialize(new Uint8Array(encryptedKeyBytes));
      const derivedPublicKeyBytes = await backendActor.public_key();
      const derivedPublicKey = DerivedPublicKey.deserialize(new Uint8Array(derivedPublicKeyBytes));
      const input = new TextEncoder().encode(normalizedName);
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
      const { primary } = await deriveAesKeyVariantsFromVetKey(vetKeyBytes);
      const phraseText = await decrypt(new Uint8Array(seedCipher), primary, new Uint8Array(seedIv));
      persistDecryptedSeed(normalizedName, phraseText);

      const seedCipherBase64 = bytesToBase64(seedCipher);
      const seedIvBase64 = bytesToBase64(seedIv);

      let imageSnapshot = null;
      // imageCipherOpt and imageIvOpt are optionals; unwrap safely and only decrypt if both exist and have data
      const imageCipherBytes =
        Array.isArray(imageCipherOpt) && imageCipherOpt.length > 0
          ? new Uint8Array(imageCipherOpt[0])
          : imageCipherOpt instanceof Uint8Array
            ? imageCipherOpt
            : null;
      const imageIvBytes =
        Array.isArray(imageIvOpt) && imageIvOpt.length > 0
          ? new Uint8Array(imageIvOpt[0])
          : imageIvOpt instanceof Uint8Array
            ? imageIvOpt
            : null;

      if (imageCipherBytes && imageCipherBytes.length > 0 && imageIvBytes && imageIvBytes.length > 0) {
        const plaintext = await decryptBytes(imageCipherBytes, primary, imageIvBytes);
        const blob = new Blob([plaintext], { type: 'image/png' });
        const url = URL.createObjectURL(blob);
        setDecryptedImages((prev) => ({ ...prev, [normalizedName]: url }));

        const imageCipherBase64 = bytesToBase64(imageCipherBytes);
        const imageIvBase64 = bytesToBase64(imageIvBytes);
        imageSnapshot = { cipher: imageCipherBase64, iv: imageIvBase64 };
      }

      setEncryptedSnapshots((prev) => ({
        ...prev,
        [normalizedName]: {
          seed: { cipher: seedCipherBase64, iv: seedIvBase64 },
          image: imageSnapshot,
        },
      }));
      await loadAccount();

      backendActor.convert_collected_icp?.().catch(() => {});
      setStatus(
        `"${normalizedName}" decrypted successfully${imageMention}. Auto-clearing in ${Math.floor(
          SEED_TTL_MS / 60000,
        )} minutes.`,
      );
    } catch (error) {
      const message = error?.message || `Failed to decrypt "${normalizedName}". Please try again.`;
      setStatus(message);
    } finally {
      setDecryptingSeeds((prev) => ({ ...prev, [seedName]: false }));
      setLoading(false);
    }
  }

  async function addImageToSeed(seedName) {
    if (!pendingImageFile) {
      setStatus('Select an image before uploading.');
      return;
    }

    const nameValidation = validateSeedNameClient(seedName);
    if (!nameValidation.ok) {
      setStatus(nameValidation.error);
      return;
    }
    const normalizedName = nameValidation.value;

    const [encryptEstimate, deriveEstimate] = await Promise.all([
      estimateCost('encrypt', 1),
      estimateCost('derive', 1),
    ]);
    const fallback = encryptEstimate.fallback_used || deriveEstimate.fallback_used;
    const required = Number(encryptEstimate.icp_e8s + deriveEstimate.icp_e8s) + LEDGER_FEE_E8S;
    const confirmed = window.confirm(
      `Encrypting an image for "${normalizedName}" will cost ~${formatIcp(required)} ICP (including ledger fee).${
        fallback ? ' (Using fallback exchange rate estimate.)' : ''
      } Continue?`,
    );
    if (!confirmed) return;

    setStatus('Preparing image upload...');
    setLoading(true);
    try {
      await waitForBalance(required, `Please transfer at least ${formatIcp(required)} ICP to proceed.`);
      const key = await deriveSymmetricKey(normalizedName);
      const { cipher, iv } = await encrypt(pendingImageFile, key);
      const result = await backendActor.add_image(normalizedName, cipher, iv);
      if ('err' in result) {
        throw new Error(result.err);
      }
      setHasImages((prev) => ({ ...prev, [normalizedName]: true }));
      setPendingImageFile(null);
      setAddingImageFor(null);
      setStatus('Image uploaded and encrypted.');
      await loadAccount();
    } catch (error) {
      const message = error?.message || 'Failed to upload image.';
      if (message.toLowerCase().includes('rate limit')) {
        setStatus(`${message} Please wait a minute and try again.`);
      } else {
        setStatus(message);
      }
    } finally {
      setLoading(false);
    }
  }


  async function deleteSeed(seedName) {
    const validation = validateSeedNameClient(seedName);
    if (!validation.ok) {
      setStatus(validation.error);
      return;
    }
    const normalizedName = validation.value;
    const confirmed = window.confirm(
      `Are you sure you want to delete "${normalizedName}"? This action cannot be undone.`,
    );
    if (!confirmed) return;

    const typed = window.prompt('Type DELETE to confirm permanent deletion of this seed.');
    if (!typed || typed.toUpperCase() !== 'DELETE') {
      setStatus('Deletion cancelled. Confirmation phrase not entered.');
      return;
    }

    setDeletingSeeds((prev) => ({ ...prev, [seedName]: true }));
    setLoading(true);
    setStatus(`Deleting "${normalizedName}"...`);
    try {
      const result = await backendActor.delete_seed(normalizedName);
      if ('err' in result) {
        throw new Error(result.err);
      }
      await loadSeeds();
      setDecryptedSeeds((prev) => {
        const updated = { ...prev };
        delete updated[normalizedName];
        return updated;
      });
      setSeedExpirations((prev) => {
        const updated = { ...prev };
        delete updated[normalizedName];
        return updated;
      });
      setDecryptedImages((prev) => {
        const updated = { ...prev };
        if (updated[normalizedName]) {
          try {
            URL.revokeObjectURL(updated[normalizedName]);
          } catch (_) {}
          delete updated[normalizedName];
        }
        return updated;
      });
      setHiddenSeeds((prev) => {
        const updated = { ...prev };
        delete updated[normalizedName];
        return updated;
      });
      if (typeof window !== 'undefined' && principalText) {
        window.sessionStorage.removeItem(seedStorageKey(principalText, normalizedName));
      }
      await loadAccount();
      setStatus(`"${normalizedName}" deleted.`);
    } catch (error) {
      setStatus(`Failed to delete "${normalizedName}". Please try again.`);
    } finally {
      setDeletingSeeds((prev) => ({ ...prev, [seedName]: false }));
      setLoading(false);
    }
  }

  async function handleAddSeed(event) {
    event.preventDefault();
    const validation = validateSeedNameClient(name);
    if (!validation.ok) {
      setStatus(validation.error);
      return;
    }
    const trimmedName = validation.value;
    const phraseValidation = validateSeedPhraseClient(phrase);
    if (!phraseValidation.ok) {
      setStatus(phraseValidation.error);
      return;
    }
    const trimmedPhrase = phraseValidation.value;
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
      estimateCost('encrypt', 1),
      estimateCost('derive', 1),
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
      let imageCipherOpt = [];
      let imageIvOpt = [];
      if (imageFile) {
        const { cipher: imgCipher, iv: imgIv } = await encrypt(imageFile, key);
        imageCipherOpt = [imgCipher];
        imageIvOpt = [imgIv];
      }
      const result = await backendActor.add_seed(trimmedName, cipher, iv, imageCipherOpt, imageIvOpt);
      if ('err' in result) {
        setStatus(result.err);
        return;
      }
      setName('');
      setPhrase('');
      setImageFile(null);
      setImagePreviewName('');
      setEncryptedSnapshots((prev) => ({
        ...prev,
        [trimmedName]: {
          seed: {
            cipher: bytesToBase64(cipher),
            iv: bytesToBase64(iv),
          },
        },
      }));
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
    const isPid = isValidPrincipal(recipient);

    if (!isPid) {
      setStatus('Invalid recipient: must be a Principal ID');
      return;
    }

    const totalE8s = amountE8s + LEDGER_FEE_E8S;

    if (accountDetails && Number(accountDetails.balance) < totalE8s) {
      setStatus(`Insufficient balance: need at least ${formatIcp(totalE8s)} ICP (including fees)`);
      return;
    }

    const confirmed = window.confirm(
      `Transfer ${transferAmount} ICP to ${recipient}? Ledger fee: ${formatIcp(LEDGER_FEE_E8S)} ICP. Total deduction: ${formatIcp(totalE8s)} ICP.`,
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
          <p>
            For questions or more details, see the README in our
            {' '}
            <a
              href="https://github.com/dickhery/seed-vault"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub repository
            </a>
            . Feel free to examine the code or deploy your own version.
          </p>
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
                    Recipient (Principal ID)
                    <input
                      required
                      value={recipient}
                      onChange={(e) => setRecipient(e.target.value.trim())}
                      placeholder="aaaaa-aa"
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
            <h2>Add a seed phrase or password</h2>
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
                Seed phrase or password
                <textarea
                  required
                  maxLength={MAX_SEED_CHARS}
                  value={phrase}
                  onChange={(e) => setPhrase(e.target.value)}
                  placeholder="Enter your seed phrase, passphrase, or password"
                />
                <p className="muted">{phrase.length}/{MAX_SEED_CHARS} characters</p>
                <p className="status warning">
                  Avoid storing secrets on shared or untrusted devices. Decrypted data is only kept in memory briefly.
                </p>
              </label>
              <label>
                Upload image (optional, max 1MB)
                <input
                  type="file"
                  accept="image/*"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (!file) {
                      setImageFile(null);
                      setImagePreviewName('');
                      return;
                    }
                    if (file.size > 1_048_576) {
                      setStatus('Image too large. Max size is 1MB.');
                      setImageFile(null);
                      setImagePreviewName('');
                      return;
                    }
                    const reader = new FileReader();
                    reader.onload = () => {
                      if (reader.result) {
                        setImageFile(new Uint8Array(reader.result));
                        setImagePreviewName(file.name);
                      }
                    };
                    reader.readAsArrayBuffer(file);
                  }}
                />
                {imagePreviewName && <p className="muted">Selected: {imagePreviewName}</p>}
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
            {showProcessingNotice && (
              <div className="processing-notice" role="status">
                Processing may take up to 45 seconds due to several backend transactions and secure key derivation on the blockchain.
                Please wait...
              </div>
            )}
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
                        <p className="seed-name">{sanitizeForHtml(seedName)}</p>
                        {decryptedSeeds[seedName] && seedExpirations[seedName] > nowTs && (
                          <>
                            <p
                              className="seed-phrase"
                              dangerouslySetInnerHTML={{
                                __html: hiddenSeeds[seedName]
                                  ? '••••••••••••••••••••••••••'
                                  : sanitizeForHtml(decryptedSeeds[seedName]),
                              }}
                            />
                            {seedExpirations[seedName] > nowTs && (
                              <p className="muted">
                                Auto-encrypt in{' '}
                                {`${Math.max(
                                  0,
                                  Math.floor((seedExpirations[seedName] - nowTs) / 1000),
                                )}s`}
                              </p>
                            )}
                            <div className="phrase-controls">
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
                                onClick={async () => {
                                  const togglingOn = !showEncrypted[seedName];
                                  if (togglingOn && !encryptedSnapshots[seedName]) {
                                    try {
                                      const seedResult = await backendActor.get_seed_cipher(seedName);
                                      if ('err' in seedResult) throw new Error(seedResult.err);
                                      const [seedCipher, seedIv] = seedResult.ok;
                                      const seedCipherBase64 = bytesToBase64(seedCipher);
                                      const seedIvBase64 = bytesToBase64(seedIv);

                                      let imageSnapshot = null;
                                      if (hasImages[seedName]) {
                                        const imageResult = await backendActor.get_image_cipher(seedName);
                                        if ('err' in imageResult) throw new Error(imageResult.err);
                                        const [imageCipher, imageIv] = imageResult.ok;
                                        if (imageCipher?.length > 0 && imageIv?.length > 0) {
                                          const imageCipherBase64 = bytesToBase64(imageCipher);
                                          const imageIvBase64 = bytesToBase64(imageIv);
                                          imageSnapshot = { cipher: imageCipherBase64, iv: imageIvBase64 };
                                        }
                                      }

                                    setEncryptedSnapshots((prev) => ({
                                      ...prev,
                                      [seedName]: {
                                        seed: { cipher: seedCipherBase64, iv: seedIvBase64 },
                                        image: imageSnapshot,
                                      },
                                    }));
                                  } catch (error) {
                                    console.error('Failed to fetch encrypted data:', error);
                                    const message = error?.message || 'Unknown error';
                                    setStatus(`Failed to fetch encrypted data: ${message}`);
                                    return;
                                  }
                                  }

                                  setShowEncrypted((prev) => ({
                                    ...prev,
                                    [seedName]: !prev[seedName],
                                  }));
                                }}
                              >
                                {showEncrypted[seedName] ? 'Show decrypted' : 'Show encrypted'}
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
                                    'Warning: Copying exposes the seed phrase to your clipboard and other apps or extensions may read it. Only continue on a trusted device.',
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
                                    setTimeout(() => {
                                      navigator.clipboard.writeText('').catch(() => {});
                                    }, 5000);
                                  } catch (error) {
                                    setStatus('Failed to copy. Please try again.');
                                  }
                                }}
                              >
                                {copyStatuses[seedName] || 'Copy'}
                              </button>
                            </div>
                            {showEncrypted[seedName] && encryptedSnapshots[seedName] && (
                              <div className="encrypted-view">
                                <p className="muted">
                                  This seed phrase is encrypted with AES-GCM and stored on-chain. Only your
                                  vetKey, derived via the Internet Computer&apos;s vetKD protocol, can decrypt it.
                                  The cipher is the encrypted data and the IV is the initialization vector used
                                  during encryption.
                                </p>
                                <p className="muted">Cipher (base64): {encryptedSnapshots[seedName].seed?.cipher}</p>
                                <p className="muted">IV (base64): {encryptedSnapshots[seedName].seed?.iv}</p>
                                {encryptedSnapshots[seedName].image && (
                                  <>
                                    <p className="muted">Encrypted image data:</p>
                                    <p className="muted">
                                      Cipher (base64): {encryptedSnapshots[seedName].image.cipher}
                                    </p>
                                    <p className="muted">IV (base64): {encryptedSnapshots[seedName].image.iv}</p>
                                  </>
                                )}
                              </div>
                            )}
                          </>
                        )}
                        {decryptedImages[seedName] && !hiddenSeeds[seedName] && (
                          <div className="image-preview">
                            <p className="muted">Decrypted image preview</p>
                            <img
                              src={decryptedImages[seedName]}
                              alt={`Seed ${seedName} attachment`}
                              onClick={() => setEnlargedImage(decryptedImages[seedName])}
                            />
                          </div>
                        )}
                      </div>
                      <div className="seed-actions">
                        {!decryptedSeeds[seedName] && (
                          <button
                            onClick={() => decryptAllForSeed(seedName)}
                            disabled={decryptingSeeds[seedName] || loading || deletingSeeds[seedName]}
                            className={decryptingSeeds[seedName] ? 'button-loading' : ''}
                          >
                            {hasImages[seedName] ? 'Decrypt seed & image' : 'Decrypt'}
                            {decryptingSeeds[seedName] && <span className="loading-spinner" />}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setAddingImageFor(seedName)}
                          disabled={loading}
                        >
                          Add image
                        </button>
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
                    {addingImageFor === seedName && (
                      <div className="callout callout-inline">
                        <p className="muted">Attach an image to "{seedName}" (max 1MB)</p>
                        <input
                          type="file"
                          accept="image/*"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (!file) {
                              setPendingImageFile(null);
                              return;
                            }
                            if (file.size > 1_048_576) {
                              setStatus('Image too large. Max size is 1MB.');
                              setPendingImageFile(null);
                              return;
                            }
                            const reader = new FileReader();
                            reader.onload = () => {
                              if (reader.result) {
                                setPendingImageFile(new Uint8Array(reader.result));
                              }
                            };
                            reader.readAsArrayBuffer(file);
                          }}
                        />
                        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                          <button type="button" onClick={() => addImageToSeed(seedName)} disabled={loading}>
                            Save image
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setAddingImageFor(null);
                              setPendingImageFile(null);
                            }}
                            disabled={loading}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
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
      {enlargedImage && (
        <div className="modal" onClick={() => setEnlargedImage(null)}>
          <img src={enlargedImage} alt="Enlarged view" />
        </div>
      )}
    </main>
  );
}

export default App;
