import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Char "mo:base/Char";
import Debug "mo:base/Debug";
import Error "mo:base/Error";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Nat8 "mo:base/Nat8";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Trie "mo:base/Trie";

persistent actor Self {
  // Type definitions for vetKD interactions
  type VetKdKeyId = { curve : { #bls12_381_g2 }; name : Text };
  type VetKdPublicKeyArgs = { canister_id : ?Principal; context : Blob; key_id : VetKdKeyId };
  type VetKdDeriveKeyArgs = { input : Blob; context : Blob; key_id : VetKdKeyId; transport_public_key : Blob };
  type EncryptedKeyReply = { encrypted_key : Blob };
  type PublicKeyReply = { public_key : Blob };

  // ICP ledger (ICRC-1) types
  type Account = { owner : Principal; subaccount : ?Blob };
  type TransferError = {
    #InsufficientFunds;
    #BadFee : { expected_fee : Nat };
    #GenericError : { error_code : Nat; message : Text };
  };
  type TransferArg = {
    from_subaccount : ?Blob;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };
  type TransferResult = { #Ok : Nat; #Err : TransferError };

  type Ledger = actor {
    icrc1_balance_of : Account -> async Nat;
    icrc1_transfer : TransferArg -> async TransferResult;
  };

  // XRC exchange rate types. Motoko reserves `class` as a keyword; the trailing
  // underscore keeps the Motoko identifier valid while Candid still serializes
  // the field name as `class` (the standard keyword-escape mapping in Motoko).
  type XrcAssetClass = variant { #Cryptocurrency; #FiatCurrency };
  // Use backtick escape so the candid field name remains `class`.
  type XrcAsset = { symbol : Text; `class` : XrcAssetClass };
  type XrcGetExchangeRateRequest = { base_asset : XrcAsset; quote_asset : XrcAsset; timestamp : ?Nat64 };

  type XrcExchangeRateMetadata = {
    decimals : Nat32;
    forex_timestamp : ?Nat64;
    base_asset_num_received_rates : Nat64;
    base_asset_num_queried_sources : Nat64;
    quote_asset_num_received_rates : Nat64;
    quote_asset_num_queried_sources : Nat64;
    standard_deviation : Nat64;
  };

  type XrcOk = {
    base_asset : XrcAsset;
    quote_asset : XrcAsset;
    timestamp : Nat64;
    rate : Nat64;
    metadata : XrcExchangeRateMetadata;
  };

  // Mirror the live XRC candid so decoding never traps when new tags appear.
  type XrcErr = variant {
    #AnonymousPrincipalNotAllowed;
    #CryptoQuoteAssetNotFound;
    #FailedToAcceptCycles;
    #ForexBaseAssetNotFound;
    #CryptoBaseAssetNotFound;
    #StablecoinRateTooFewRates;
    #ForexAssetsNotFound;
    #InconsistentRatesReceived;
    #RateLimited;
    #StablecoinRateZeroRate;
    #Other : { code : Nat32; description : Text };
    #ForexInvalidTimestamp;
    #NotEnoughCycles;
    #ForexQuoteAssetNotFound;
    #StablecoinRateNotFound;
    #Pending;
  };

  type XrcGetExchangeRateResult = variant { #Ok : XrcOk; #Err : XrcErr };
  type Xrc = actor {
    // XRC is an update call that requires cycles; declaring it as such ensures cycles
    // are attached and the request is accepted.
    get_exchange_rate : shared (XrcGetExchangeRateRequest) -> async XrcGetExchangeRateResult;
  };

  // Call the management canister directly for vetKD.
  type VetKdApi = actor {
    vetkd_public_key : VetKdPublicKeyArgs -> async PublicKeyReply;
    vetkd_derive_key : VetKdDeriveKeyArgs -> async EncryptedKeyReply;
  };

  type NotifyArg = { block_index : Nat64 };
  type CyclesMintingCanister = actor {
    notify_mint_cycles : NotifyArg -> async ();
  };

  // Cycles ledger (ICRC-1/2/3) minimal surface used for withdrawals.
  type CyclesLedgerAccount = { owner : Principal; subaccount : ?[Nat8] };
  type CyclesWithdrawArgs = {
    amount : Nat;
    from_subaccount : ?[Nat8];
    to : Principal;
    created_at_time : ?Nat64;
  };
  type CyclesWithdrawError = {
    #GenericError : { message : Text; error_code : Nat };
    #TemporarilyUnavailable;
    #Duplicate : { duplicate_of : Nat };
    #BadFee : { expected_fee : Nat };
    #InvalidReceiver : { receiver : Principal };
    #CreatedInFuture : { ledger_time : Nat64 };
    #TooOld;
    #InsufficientFunds : { balance : Nat };
    #FailedToWithdraw : {
      rejection_code : { #NoError; #CanisterError; #SysTransient; #DestinationInvalid; #Unknown; #SysFatal; #CanisterReject };
      rejection_reason : Text;
      fee_block : ?Nat;
    };
  };
  type CyclesWithdrawResult = { #Ok : Nat; #Err : CyclesWithdrawError };
  type CyclesLedger = actor {
    icrc1_balance_of : CyclesLedgerAccount -> async Nat;
    withdraw : CyclesWithdrawArgs -> async CyclesWithdrawResult;
  };

  let IC : VetKdApi = actor "aaaaa-aa";
  // Ledger actor reference recreated per call to avoid stable-type compatibility issues across upgrades.
  private func ledger() : Ledger = actor ("ryjl3-tyaaa-aaaaa-aaaba-cai") : Ledger;
  let XRC : Xrc = actor "uf6dk-hyaaa-aaaaq-qaaaq-cai";
  let CYCLES_LEDGER : CyclesLedger = actor "um5iw-rqaaa-aaaaq-qaaba-cai";

  // Keep domain separator as a blob and convert to bytes when building the vetKD context.
  let DOMAIN_SEPARATOR : Blob = Text.encodeUtf8("seed-vault-app");

  let ICP_TRANSFER_FEE : Nat = 10_000;
  let CYCLES_PER_XDR : Nat = 1_000_000_000_000;
  let ICP_PER_XDR_FALLBACK : Nat = 50_000_000; // 0.5 ICP in e8s fallback
  let MAX_OPERATION_COST_E8S : Nat = 100_000_000; // Safety cap: 1 ICP
  let MAX_RATE_DEVIATION_PERCENT : Nat = 10; // Reject fresh rates that drift too far from cached values
  // 420 UTF-8 characters can expand to ~1680 bytes in the worst case; AES-GCM adds
  // a 16-byte tag, so we reject ciphertexts above 2 KB to enforce the character limit
  // even if the frontend is bypassed.
  let MAX_SEED_CIPHER_BYTES : Nat = 2_048;
  let MAX_IMAGE_BYTES : Nat = 1_048_576; // 1 MB limit for encrypted image payloads
  let MAX_SEED_NAME_CHARS : Nat = 100;
  let MAX_SEEDS_PER_USER : Nat = 50;
  let ENCRYPT_CYCLE_COST : Nat = 1_000_000_000; // ~1B cycles per encrypt
  let DECRYPT_CYCLE_COST : Nat = 500_000_000; // ~0.5B cycles per decrypt
  let PRICING_REFRESH_INTERVAL_NS : Int = 60_000_000_000; // 1 minute
  let FALLBACK_RETRY_INTERVAL_NS : Int = 60_000_000_000; // 1 minute between fallback retries
  // The XRC requires at least 1B cycles to be attached to each request. Send a
  // larger allowance so we avoid intermittent `NotEnoughCycles` rejections on
  // busier subnets and during cache misses, which otherwise force the UI to fall
  // back to stale pricing and show zero/near-zero costs.
  let XRC_CALL_CYCLES : Nat = 100_000_000_000;
  // Match the cycles attached in vetkd_derive_key so pricing reflects the
  // actual derivation cost instead of an inflated estimate.
  let DERIVE_CYCLE_COST : Nat = 26_153_846_153;
  // Withdraw fee on cycles ledger (100M cycles).
  let CYCLES_WITHDRAW_FEE : Nat = 100_000_000;
  // Add a small buffer so we can pay the fee to convert collected ICP into cycles.
  let ICP_TO_CYCLES_BUFFER_E8S : Nat = ICP_TRANSFER_FEE * 3;
  let CMC_PRINCIPAL : Principal = Principal.fromText("rkp4c-7iaaa-aaaaa-aaaca-cai");
  let MINT_MEMO : Blob = Blob.fromArray([77, 73, 78, 84, 0, 0, 0, 0]); // "MINT\00\00\00\00"
  let CMC : CyclesMintingCanister = actor (Principal.toText(CMC_PRINCIPAL));

  type Seed = {
    name : Text;
    seed_cipher : Blob;
    seed_iv : Blob;
    image_cipher : ?Blob;
    image_iv : ?Blob;
  };

  // Legacy storage (name, seed_cipher, seed_iv) preserved for upgrade compatibility.
  stable var seedsByOwner : [(Principal, [(Text, Blob, Blob)])] = [];
  // Current storage mapping owner -> list of seeds (including optional images).
  stable var seedsByOwnerV2 : [(Principal, [Seed])] = [];
  // Remember the last successful XRC XDR/ICP rate so pricing stays fresh even if a later call fails.
  stable var last_xdr_per_icp_rate : Nat = 0;
  // Track when pricing was last refreshed so the frontend can present a meaningful timestamp and we can
  // throttle exchange-rate lookups to avoid unnecessary XRC calls.
  stable var last_xdr_refresh_ns : Int = 0;
  // Whether the most recent pricing refresh had to rely on the fallback rate instead of a live XRC response.
  stable var last_pricing_fallback_used : Bool = false;
  // Track per-user operation counts for rate limiting.
  stable var userOps : Trie.Trie<Principal, (Nat, Int)> = Trie.empty();
  // Track aggregate operations across all callers to mitigate Sybil-style rate limit bypasses.
  stable var globalOps : Nat = 0;
  stable var globalResetNs : Int = 0;
  // Persist per-user audit events (timestamp, description) for a short access history.
  stable var auditLogs : Trie.Trie<Principal, [(Int, Text)]> = Trie.empty();

  // Allow extremely high per-user and global throughput while retaining a short reset
  // window so legitimate bursts are never throttled during testing or heavy usage.
  let RATE_LIMIT : Nat = 1_000_000; // operations per reset interval
  let GLOBAL_RATE_LIMIT : Nat = 10_000_000; // overall operations per reset interval
  let RESET_INTERVAL : Int = 60_000_000_000; // 1 minute in nanoseconds

  // Upgrade migration: convert legacy tuple-based seeds into the richer Seed record format.
  private func ensureSeedsMigrated() {
    if (seedsByOwnerV2.size() == 0 and seedsByOwner.size() > 0) {
      let migrated = Array.tabulate<(Principal, [Seed])>(
        seedsByOwner.size(),
        func(i : Nat) : (Principal, [Seed]) {
          let (owner, legacySeeds) = seedsByOwner[i];
          let converted = Array.tabulate<Seed>(
            legacySeeds.size(),
            func(j : Nat) : Seed {
              let (n, c, iv) = legacySeeds[j];
              {
                name = n;
                seed_cipher = c;
                seed_iv = iv;
                image_cipher = null;
                image_iv = null;
              }
            },
          );
          (owner, converted)
        },
      );
      seedsByOwnerV2 := migrated;
      // Clear legacy data to avoid double-charging storage and keep future upgrades simpler.
      seedsByOwner := [];
    };
  };

  private func findOwnerIndex(owner : Principal) : ?Nat {
    ensureSeedsMigrated();
    var i : Nat = 0;
    while (i < seedsByOwnerV2.size()) {
      let (p, _) = seedsByOwnerV2[i];
      if (Principal.equal(p, owner)) {
        return ?i;
      };
      i += 1;
    };
    null;
  };

  private func sameName(a : Text, b : Text) : Bool {
    Text.equal(normalizeName(a), normalizeName(b))
  };

  private func hasSeedName(seeds : [Seed], name : Text) : Bool {
    var i : Nat = 0;
    while (i < seeds.size()) {
      let s = seeds[i];
      if (sameName(s.name, name)) {
        return true;
      };
      i += 1;
    };
    false;
  };

  private func normalizeName(name : Text) : Text {
    Text.trim(name, #predicate(Char.isWhitespace))
  };

  private func isValidSeedName(name : Text) : Bool {
    let trimmed = normalizeName(name);
    if (Text.size(trimmed) == 0) {
      return false;
    };

    let chars = Text.toArray(trimmed);
    let first = chars[0];
    let last = chars[chars.size() - 1];
    if (Char.equal(first, '-') or Char.equal(first, '_') or Char.equal(last, '-') or Char.equal(last, '_')) {
      return false;
    };
    var i : Nat = 0;
    while (i < chars.size()) {
      let c = chars[i];
      if (
        not (Char.isAlphabetic(c) or Char.isDigit(c) or Char.equal(c, ' ') or Char.equal(c, '-') or Char.equal(c, '_'))
      ) {
        return false;
      };
      i += 1;
    };
    true;
  };

  private func keyId() : VetKdKeyId {
    // Use the production key on mainnet; switch to "test_key_1" if you want cheaper testing.
    { curve = #bls12_381_g2; name = "key_1" };
  };

  private func callerKey(principal : Principal) : Trie.Key<Principal> {
    { key = principal; hash = Principal.hash(principal) }
  };

  private func audit(event : Text, caller : Principal) {
    let ts = Time.now();
    Debug.print("[audit] " # event # " | caller=" # Principal.toText(caller) # " | ts=" # Int.toText(ts));

    let key = callerKey(caller);
    let existing = switch (Trie.find(auditLogs, key, Principal.equal)) {
      case (?entries) { entries };
      case null { [] };
    };
    let updatedEntries = Array.append<(Int, Text)>(existing, [(ts, event)]);
    let (newTrie, _) = Trie.put(auditLogs, key, Principal.equal, updatedEntries);
    auditLogs := newTrie;
  };

  private func checkRateLimit(caller : Principal) : Result.Result<(), Text> {
    let now = Time.now();
    let key = callerKey(caller);

    if (now - globalResetNs >= RESET_INTERVAL) {
      globalOps := 0;
      globalResetNs := now;
    };
    if (globalOps >= GLOBAL_RATE_LIMIT) {
      let retryNs = RESET_INTERVAL - (now - globalResetNs);
      let retryMs = if (retryNs > 0) { retryNs / 1_000_000 } else { 0 };
      return #err(
        "Global rate limit reached. Please retry in ~" # Int.toText(retryMs) # " ms to protect other users.",
      );
    };
    globalOps += 1;

    switch (Trie.find(userOps, key, Principal.equal)) {
      case (? (count, lastReset)) {
        if (now - lastReset >= RESET_INTERVAL) {
          let (updatedTrie, _) = Trie.put(userOps, key, Principal.equal, (1, now));
          userOps := updatedTrie;
          #ok(())
        } else if (count >= RATE_LIMIT) {
          let retryNs = RESET_INTERVAL - (now - lastReset);
          let retryMs = if (retryNs > 0) { retryNs / 1_000_000 } else { 0 };
          #err("Rate limit exceeded. Try again in ~" # Int.toText(retryMs) # " ms.")
        } else {
          let (updatedTrie, _) = Trie.put(userOps, key, Principal.equal, (count + 1, lastReset));
          userOps := updatedTrie;
          #ok(())
        }
      };
      case null {
        let (updatedTrie, _) = Trie.put(userOps, key, Principal.equal, (1, now));
        userOps := updatedTrie;
        #ok(())
      };
    }
  };

  private func subaccount(principal : Principal) : Blob {
    let raw = Blob.toArray(Principal.toBlob(principal));
    let padded = Array.tabulate<Nat8>(32, func(i : Nat) : Nat8 {
      if (i < raw.size()) {
        raw[i]
      } else {
        0
      }
    });
    Blob.fromArray(padded);
  };

  // CMC expects a length-prefixed subaccount derived from the caller principal.
  private func cmcSubaccount(principal : Principal) : Blob {
    let raw = Blob.toArray(Principal.toBlob(principal));
    let padded = Array.tabulate<Nat8>(32, func(i : Nat) : Nat8 {
      if (i == 0) {
        Nat8.fromNat(raw.size())
      } else if (i <= raw.size()) {
        raw[i - 1]
      } else {
        0
      }
    });
    Blob.fromArray(padded)
  };

  private func refreshXdrRate() : async { rate : Nat; fallback_used : Bool } {
    let now = Time.now();

    if (last_xdr_per_icp_rate != 0) {
      let sinceLast = now - last_xdr_refresh_ns;

      if (not last_pricing_fallback_used and sinceLast < PRICING_REFRESH_INTERVAL_NS) {
        return { rate = last_xdr_per_icp_rate; fallback_used = last_pricing_fallback_used };
      };

      if (last_pricing_fallback_used and sinceLast < FALLBACK_RETRY_INTERVAL_NS) {
        return { rate = last_xdr_per_icp_rate; fallback_used = true };
      };
    };

    let request : XrcGetExchangeRateRequest = {
      base_asset = { symbol = "ICP"; `class` = #Cryptocurrency };
      quote_asset = { symbol = "XDR"; `class` = #FiatCurrency };
      timestamp = null;
    };
    // Conservative fallback XDR/ICP to overestimate cost when live pricing fails,
    // preventing under-billing that could leave the canister without enough cycles
    // to complete vetKD calls.
    let fallback_rate : Nat = 500_000_000;
    var balance = ExperimentalCycles.balance();
    var fallbackUsed = false;

    // If we're short on cycles for an XRC call but have ICP sitting in the default
    // account, opportunistically convert a portion so we can avoid stale pricing.
    if (balance < XRC_CALL_CYCLES) {
      let selfPrincipal = Principal.fromActor(Self);
      let defaultAccount : Account = { owner = selfPrincipal; subaccount = null };
      let icpBalance = try {
        await ledger().icrc1_balance_of(defaultAccount)
      } catch (_) { 0 };

      // Leave the transfer fee untouched so we can pay for the conversion itself.
      if (icpBalance > ICP_TO_CYCLES_BUFFER_E8S) {
        let convertible = icpBalance - ICP_TO_CYCLES_BUFFER_E8S;
        switch (await convertToCycles(convertible)) {
          case (#ok(())) {
            balance := ExperimentalCycles.balance();
          };
          case (#err(_)) {};
        };
      };
    };

    let MIN_XRC_CYCLES : Nat = 500_000_000;
    if (balance < MIN_XRC_CYCLES) {
      let selfPrincipal = Principal.fromActor(Self);
      let defaultAccount : Account = { owner = selfPrincipal; subaccount = null };
      let icpBalance = try {
        await ledger().icrc1_balance_of(defaultAccount)
      } catch (_) { 0 };

      if (icpBalance > ICP_TO_CYCLES_BUFFER_E8S) {
        let convertible = icpBalance - ICP_TO_CYCLES_BUFFER_E8S;
        switch (await convertToCycles(convertible)) {
          case (#ok(())) {
            balance := ExperimentalCycles.balance();
          };
          case (#err(_)) {};
        };
      };
    };

    var attempts : Nat = 0;
    var rateResult : XrcGetExchangeRateResult = #Err(#Other { code = Nat32.fromNat(0); description = "xrc not attempted" });
    label retries while (attempts < 20) {
      let to_add = Nat.min(balance, XRC_CALL_CYCLES);
      if (to_add < MIN_XRC_CYCLES) {
        fallbackUsed := true;
        break retries;
      };

      ExperimentalCycles.add(to_add);
      let attempt : XrcGetExchangeRateResult = try {
        await XRC.get_exchange_rate(request)
      } catch (_) { #Err(#Other { code = Nat32.fromNat(0); description = "xrc unavailable" }) };

      switch (attempt) {
        case (#Ok(_)) {
          rateResult := attempt;
          break retries;
        };
        case (#Err(_)) {
          attempts += 1;
          if (attempts >= 20) {
            rateResult := attempt;
            fallbackUsed := true;
          };
        };
      };

      balance := ExperimentalCycles.balance();
    };

    let rateNat : Nat = switch (rateResult) {
      case (#Ok({ rate })) {
        let r = Nat64.toNat(rate);
        let accepted = if (last_xdr_per_icp_rate == 0) {
          r
        } else {
          let lowerBound = (last_xdr_per_icp_rate * (100 - MAX_RATE_DEVIATION_PERCENT)) / 100;
          let upperBound = (last_xdr_per_icp_rate * (100 + MAX_RATE_DEVIATION_PERCENT)) / 100;
          if (r < lowerBound or r > upperBound) {
            fallbackUsed := true;
            last_xdr_per_icp_rate
          } else {
            r
          }
        };
        last_xdr_per_icp_rate := accepted;
        last_pricing_fallback_used := fallbackUsed;
        last_xdr_refresh_ns := now;
        accepted
      };
      case (#Err(err)) {
        fallbackUsed := true;
        let errMsg = switch (err) {
          case (#NotEnoughCycles) { "not enough cycles" };
          case (#RateLimited) { "rate limited" };
          case (#Other { description }) { "other: " # description };
          case (_) { "unhandled" };
        };
        Debug.print("[XRC] Error: " # errMsg);
        let rateChoice = if (last_xdr_per_icp_rate > 0) { last_xdr_per_icp_rate } else { fallback_rate };
        if (last_xdr_per_icp_rate == 0) {
          last_xdr_per_icp_rate := rateChoice;
        };
        last_pricing_fallback_used := true;
        last_xdr_refresh_ns := now;
        rateChoice
      };
    };
    Debug.print(
      "[XRC] Refresh at " # Int.toText(now) # " result=" # debug_show(rateResult) # " rate=" # Nat.toText(rateNat)
      # " fallback=" # debug_show(fallbackUsed),
    );
    { rate = if (rateNat == 0) { 1 } else { rateNat }; fallback_used = fallbackUsed };
  };

  private func cyclesToIcp(cycles : Nat) : async { icp_e8s : Nat; fallback_used : Bool } {
    if (cycles == 0) {
      return { icp_e8s = 0; fallback_used = false };
    };

    let { rate; fallback_used } = await refreshXdrRate();
    Debug.print(
      "[cyclesToIcp] Cycles=" # Nat.toText(cycles) # " rate=" # Nat.toText(rate) # " fallback=" # debug_show(fallback_used),
    );
    let numerator : Nat = cycles * 100_000;
    let baseCost = numerator / rate;
    // Add a ~5% buffer to account for execution and rounding without meaningfully
    // overcharging the caller.
    let buffered = (baseCost * 105) / 100;
    { icp_e8s = buffered + ICP_TO_CYCLES_BUFFER_E8S; fallback_used };
  };

  private func operationCycles(operation : Text, count : Nat) : Nat {
    if (Text.equal(operation, "encrypt")) {
      ENCRYPT_CYCLE_COST * count
    } else if (Text.equal(operation, "decrypt")) {
      DECRYPT_CYCLE_COST * count
    } else if (Text.equal(operation, "derive")) {
      DERIVE_CYCLE_COST * count
    } else {
      0
    };
  };

  private func assertCostWithinLimit(icp_e8s : Nat) : Result.Result<(), Text> {
    if (icp_e8s > MAX_OPERATION_COST_E8S) {
      #err("Estimated cost exceeds safety cap. Please retry later or contact support.")
    } else {
      #ok(())
    }
  };

  // Convert collected ICP into cycles by sending ICP to the CMC and notifying it,
  // then withdrawing the minted cycles from the cycles ledger back into this canister.
  private func convertToCycles(amount : Nat) : async Result.Result<(), Text> {
    if (amount == 0) {
      return #ok(());
    };

    let selfPrincipal = Principal.fromActor(Self);
    let defaultAccount : Account = { owner = selfPrincipal; subaccount = null };
    let balance = try {
      await ledger().icrc1_balance_of(defaultAccount)
    } catch (e) {
      return #err("Unable to check canister balance: " # Error.message(e));
    };

    if (balance < amount + ICP_TRANSFER_FEE) {
      return #err("Insufficient ICP in canister to convert to cycles");
    };

    let cmcAccount : Account = { owner = CMC_PRINCIPAL; subaccount = ?cmcSubaccount(selfPrincipal) };
    let transferArgs : TransferArg = {
      from_subaccount = null;
      to = cmcAccount;
      amount = amount;
      fee = ?ICP_TRANSFER_FEE;
      memo = ?MINT_MEMO;
      created_at_time = null;
    };

    let transferResult = try {
      await ledger().icrc1_transfer(transferArgs)
    } catch (e) {
      return #err("Failed to transfer to CMC: " # Error.message(e));
    };

    switch (transferResult) {
      case (#Err(#InsufficientFunds)) { return #err("CMC transfer: insufficient funds") };
      case (#Err(#BadFee({ expected_fee }))) {
        return #err("CMC transfer: incorrect fee. Expected " # Nat.toText(expected_fee))
      };
      case (#Err(#GenericError({ message }))) {
        return #err("CMC transfer error: " # message)
      };
      case (#Ok(blockIndex)) {
        let notifyArgs : NotifyArg = { block_index = Nat64.fromNat(blockIndex) };
        try {
          await CMC.notify_mint_cycles(notifyArgs);

          // Minted cycles land in the cycles ledger; withdraw them into this canister.
          let ledgerAccount : CyclesLedgerAccount = { owner = selfPrincipal; subaccount = null };
          let mintedBalance = try { await CYCLES_LEDGER.icrc1_balance_of(ledgerAccount) } catch (e) {
            return #err("Cycles ledger unavailable: " # Error.message(e))
          };

          if (mintedBalance < CYCLES_WITHDRAW_FEE + 100_000_000) {
            return #err("CMC notify succeeded but minted balance (" # Nat.toText(mintedBalance) # ") is not enough to withdraw")
          };

          let withdrawAmount = mintedBalance - CYCLES_WITHDRAW_FEE;
          let beforeCycles = ExperimentalCycles.balance();
          let withdrawResult = try {
            await CYCLES_LEDGER.withdraw({
              amount = withdrawAmount;
              from_subaccount = null;
              to = selfPrincipal;
              created_at_time = null;
            })
          } catch (e) {
            return #err("Cycles ledger withdraw failed: " # Error.message(e))
          };

          switch (withdrawResult) {
            case (#Ok(_)) {
              let afterCycles = ExperimentalCycles.balance();
              if (afterCycles > beforeCycles) { #ok(()) } else {
                #err("Cycles withdraw completed but canister cycles did not increase")
              }
            };
            case (#Err(err)) {
              #err("Cycles ledger withdraw error: " # debug_show(err))
            };
          };
        } catch (e) {
          #err("CMC notify failed: " # Error.message(e) # ". Cycles may not have been minted—check ledger.")
        };
      };
    };
  };

  private func chargeUser(caller : Principal, amount : Nat) : async Result.Result<Nat, Text> {
    let callerSub = subaccount(caller);
    let account : Account = { owner = Principal.fromActor(Self); subaccount = ?callerSub };

    let balance = try {
      await ledger().icrc1_balance_of(account)
    } catch (e) {
      return #err("Ledger unavailable: " # Error.message(e));
    };
    if (balance < amount + ICP_TRANSFER_FEE) {
      return #err("Insufficient balance. Please transfer more ICP to proceed.");
    };

    let transferResult = try {
      await ledger().icrc1_transfer({
        from_subaccount = ?callerSub;
        to = { owner = Principal.fromActor(Self); subaccount = null };
        amount = amount;
        fee = ?ICP_TRANSFER_FEE;
        memo = null;
        created_at_time = null;
      })
    } catch (e) {
      return #err("Ledger transfer failed: " # Error.message(e));
    };

    switch (transferResult) {
      case (#Ok(block)) { #ok(block) };
      case (#Err(#InsufficientFunds)) { #err("Ledger reports insufficient funds") };
      case (#Err(#BadFee({ expected_fee }))) {
        #err("Incorrect fee. Expected " # Nat.toText(expected_fee))
      };
      case (#Err(#GenericError({ message }))) {
        #err("Ledger error: " # message)
      };
    };
  };

  // Attempt to refund previously charged ICP back to the caller's subaccount.
  private func refundUser(caller : Principal, amount : Nat, context : Text) : async () {
    if (amount <= ICP_TRANSFER_FEE) {
      return;
    };

    let refundable = amount - ICP_TRANSFER_FEE;
    let toAccount : Account = { owner = Principal.fromActor(Self); subaccount = ?subaccount(caller) };

    try {
      let result = await ledger().icrc1_transfer({
        from_subaccount = null;
        to = toAccount;
        amount = refundable;
        fee = ?ICP_TRANSFER_FEE;
        memo = null;
        created_at_time = null;
      });

      switch (result) {
        case (#Ok(_)) { audit("Refunded user after failure: " # context, caller) };
        case (#Err(err)) {
          audit("Refund attempt failed: " # debug_show(err) # " | context=" # context, caller);
        };
      };
    } catch (e) {
      audit("Refund error: " # Error.message(e) # " | context=" # context, caller);
    };
  };

  private func validateRequestedName(name : Text) : Result.Result<Text, Text> {
    let normalized = normalizeName(name);
    if (Text.size(normalized) == 0) {
      return #err("Name cannot be empty");
    };
    if (Text.size(normalized) > MAX_SEED_NAME_CHARS) {
      return #err("Name too long. Maximum 100 characters.");
    };
    if (not isValidSeedName(normalized)) {
      return #err("Invalid characters in name. Allowed: letters, digits, spaces, hyphens, underscores.");
    };
    #ok(normalized)
  };

  private func context(principal : Principal) : Blob {
    let principalBytes : [Nat8] = Blob.toArray(Principal.toBlob(principal));
    let dom : [Nat8] = Blob.toArray(DOMAIN_SEPARATOR);
    let size = Nat8.fromNat(dom.size());
    let sizeArr : [Nat8] = [size];
    let withDomain : [Nat8] = Array.append(sizeArr, dom);
    let flattened : [Nat8] = Array.append(withDomain, principalBytes);
    Blob.fromArray(flattened);
  };

  public shared ({ caller }) func public_key() : async Blob {
    let { public_key } = await IC.vetkd_public_key({
      canister_id = null;
      context = context(caller);
      key_id = keyId();
    });
    public_key;
  };

  public shared ({ caller }) func get_account_details() : async {
    owner : Text;
    canister : Text;
    subaccount : Blob;
    balance : Nat;
  } {
    let callerSub = subaccount(caller);
    let account : Account = { owner = Principal.fromActor(Self); subaccount = ?callerSub };
    let balance = try {
      await ledger().icrc1_balance_of(account)
    } catch (_) {
      0
    };
    {
      owner = Principal.toText(caller);
      canister = Principal.toText(Principal.fromActor(Self));
      subaccount = callerSub;
      balance;
    };
  };

  public shared ({ caller }) func transfer_icp(to_text : Text, amount : Nat) : async Result.Result<Nat, Text> {
    if (amount == 0) {
      return #err("Amount must be greater than zero");
    };

    let callerSub = subaccount(caller);
    let userAccount : Account = { owner = Principal.fromActor(Self); subaccount = ?callerSub };
    let balance = try {
      await ledger().icrc1_balance_of(userAccount)
    } catch (e) {
      return #err("Ledger unavailable: " # Error.message(e));
    };

    let principalRecipient : ?Principal = try {
      ?Principal.fromText(to_text)
    } catch (_) { null };

    switch (principalRecipient) {
      case null { return #err("Invalid recipient: must be a principal ID") };
      case (?toPrincipal) {
        let required = amount + ICP_TRANSFER_FEE;
        if (balance < required) {
          return #err("Insufficient balance to cover amount and fees");
        };

        let transferResult = try {
          await ledger().icrc1_transfer({
            from_subaccount = ?callerSub;
            to = { owner = toPrincipal; subaccount = null };
            amount = amount;
            fee = ?ICP_TRANSFER_FEE;
            memo = null;
            created_at_time = null;
          })
        } catch (e) {
          return #err("Ledger transfer failed: " # Error.message(e));
        };

        switch (transferResult) {
          case (#Ok(block)) { #ok(block) };
          case (#Err(#InsufficientFunds)) { #err("Ledger reports insufficient funds") };
          case (#Err(#BadFee({ expected_fee }))) {
            #err("Incorrect fee. Expected " # Nat.toText(expected_fee))
          };
          case (#Err(#GenericError({ message }))) { #err("Ledger error: " # message) };
        };
      };
    };
  };

  private func estimateCostInternal(operation : Text, count : Nat, caller : Principal) : async {
    cycles : Nat;
    icp_e8s : Nat;
    fallback_used : Bool;
  } {
    switch (checkRateLimit(caller)) {
      case (#err(_)) { return { cycles = 0; icp_e8s = 0; fallback_used = true } };
      case (#ok(())) {};
    };

    let cycles = operationCycles(operation, count);
    let { icp_e8s; fallback_used } = await cyclesToIcp(cycles);
    var capped = icp_e8s;
    var fallback = fallback_used;
    if (icp_e8s > MAX_OPERATION_COST_E8S) {
      capped := MAX_OPERATION_COST_E8S;
      fallback := true;
    };
    { cycles; icp_e8s = capped; fallback_used = fallback };
  };

  public shared ({ caller }) func estimate_cost(operation : Text, count : Nat) : async {
    cycles : Nat;
    icp_e8s : Nat;
    fallback_used : Bool;
  } {
    await estimateCostInternal(operation, count, caller);
  };

  // Backward-compatible estimator that accepts a record so argument ordering mismatches
  // in generated bindings cannot trigger a decode trap. The frontend sends a record and
  // falls back to the tuple-based legacy signature if needed.
  public shared ({ caller }) func estimate_cost_v2(args : { operation : Text; count : Nat }) : async {
    cycles : Nat;
    icp_e8s : Nat;
    fallback_used : Bool;
  } {
    await estimateCostInternal(args.operation, args.count, caller);
  };

  public query ({ caller }) func seed_count() : async Nat {
    switch (findOwnerIndex(caller)) {
      case (?idx) { let (_, seeds) = seedsByOwnerV2[idx]; seeds.size() };
      case null { 0 };
    };
  };

  public query ({ caller }) func get_seed_names() : async [{ name : Text; has_image : Bool }] {
    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        Array.map<Seed, { name : Text; has_image : Bool }>(
          seeds,
          func(s : Seed) : { name : Text; has_image : Bool } {
            { name = s.name; has_image = switch (s.image_cipher) { case (?_) true; case null false } };
          },
        );
      };
      case null { [] };
    };
  };

  public shared ({ caller }) func encrypted_symmetric_key_for_seed(name : Text, transport_public_key : Blob) : async Blob {
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { throw Error.reject(msg) };
      case (#ok(n)) { n };
    };
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { throw Error.reject(msg) };
      case (#ok(())) {};
    };

    let { icp_e8s } = await estimate_cost("derive", 1);
    switch (assertCostWithinLimit(icp_e8s)) {
      case (#err(msg)) { throw Error.reject(msg) };
      case (#ok(())) {};
    };
    var charged = false;

    switch (await chargeUser(caller, icp_e8s)) {
      case (#err(msg)) { throw Error.reject(msg) };
      case (#ok(_)) { charged := true };
    };

    try {
      let input : Blob = Text.encodeUtf8(normalizedName);
      let { encrypted_key } = await (with cycles = 26_153_846_153) IC.vetkd_derive_key({
        input;
        context = context(caller);
        key_id = keyId();
        transport_public_key;
      });

      let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
      ignore await convertToCycles(amountToConvert);
      audit("Derived encrypted symmetric key for seed", caller);
      encrypted_key;
    } catch (e) {
      if (charged) {
        await refundUser(caller, icp_e8s, "derive key: " # Error.message(e));
      };
      throw Error.reject("Failed to derive encrypted key");
    };
  };

  public shared ({ caller }) func add_seed(
    name : Text,
    cipher : Blob,
    iv : Blob,
    image_cipher : ?Blob,
    image_iv : ?Blob,
  ) : async Result.Result<(), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };
    let cipherArr = Blob.toArray(cipher);
    if (cipherArr.size() == 0) {
      return #err("Ciphertext cannot be empty");
    };
    if (cipherArr.size() > MAX_SEED_CIPHER_BYTES) {
      return #err("Seed phrase too long. Limit is 420 characters.");
    };
    switch (image_cipher, image_iv) {
      case (?imgCipher, ?imgIv) {
        let imgArr = Blob.toArray(imgCipher);
        if (imgArr.size() == 0) {
          return #err("Image ciphertext cannot be empty");
        };
        if (imgArr.size() > MAX_IMAGE_BYTES) {
          return #err("Encrypted image is too large. Limit is 1 MB.");
        };
        if (Blob.toArray(imgIv).size() == 0) {
          return #err("Image IV cannot be empty");
        };
      };
      case _ {};
    };

    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        if (seeds.size() >= MAX_SEEDS_PER_USER) {
          return #err("Maximum number of seeds reached. Delete one before adding another.");
        };
        if (hasSeedName(seeds, normalizedName)) {
          return #err("Name already exists for this user");
        };
      };
      case null {};
    };

    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };

    var encryptOps : Nat = 1;
    switch (image_cipher) {
      case (?_) { encryptOps += 1 };
      case null {};
    };

    let { icp_e8s } = await estimate_cost("encrypt", encryptOps);
    switch (assertCostWithinLimit(icp_e8s)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    var charged = false;
    let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };

    if (icp_e8s > 0) {
      switch (await chargeUser(caller, icp_e8s)) {
        case (#err(msg)) { return #err(msg) };
        case (#ok(_)) { charged := true };
      };
    };

    try {
      let newSeed : Seed = {
        name = normalizedName;
        seed_cipher = cipher;
        seed_iv = iv;
        image_cipher = image_cipher;
        image_iv = image_iv;
      };

      switch (findOwnerIndex(caller)) {
        case (?idx) {
          let (_, seeds) = seedsByOwnerV2[idx];
          let updatedSeeds = Array.append<Seed>(seeds, [newSeed]);
          let updatedOwners = Array.tabulate<(Principal, [Seed])>(
            seedsByOwnerV2.size(),
            func(j : Nat) : (Principal, [Seed]) {
              if (j == idx) {
                (caller, updatedSeeds)
              } else {
                seedsByOwnerV2[j]
              }
            },
          );
          seedsByOwnerV2 := updatedOwners;
        };
        case null {
          seedsByOwnerV2 := Array.append<(Principal, [Seed])>(seedsByOwnerV2, [(caller, [newSeed])]);
        };
      };

      if (icp_e8s > 0) {
        ignore await convertToCycles(amountToConvert);
      };
      audit("Added seed " # normalizedName, caller);
      #ok(());
    } catch (e) {
      if (charged) {
        await refundUser(caller, icp_e8s, "add seed: " # Error.message(e));
      };
      #err("Failed to save seed. Please try again.");
    };
  };

  public shared ({ caller }) func delete_seed(name : Text) : async Result.Result<(), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (owner, seeds) = seedsByOwnerV2[idx];
        let filtered = Array.filter<Seed>(seeds, func(s : Seed) : Bool { not sameName(s.name, normalizedName) });
        if (filtered.size() == seeds.size()) {
          return #err("Seed not found: " # normalizedName);
        };

        let updatedOwners = Array.tabulate<(Principal, [Seed])>(
          seedsByOwnerV2.size(),
          func(j : Nat) : (Principal, [Seed]) {
            if (j == idx) {
              (owner, filtered)
            } else {
              seedsByOwnerV2[j]
            }
          },
        );
        seedsByOwnerV2 := updatedOwners;
        audit("Deleted seed " # normalizedName, caller);
        #ok(());
      };
    };
  };

  public shared ({ caller }) func add_image(
    name : Text,
    image_cipher : Blob,
    image_iv : Blob,
  ) : async Result.Result<(), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };

    let imgArr = Blob.toArray(image_cipher);
    if (imgArr.size() == 0) {
      return #err("Image ciphertext cannot be empty");
    };
    if (imgArr.size() > MAX_IMAGE_BYTES) {
      return #err("Encrypted image is too large. Limit is 1 MB.");
    };
    if (Blob.toArray(image_iv).size() == 0) {
      return #err("Image IV cannot be empty");
    };

    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };

    let { icp_e8s } = await estimate_cost("encrypt", 1);
    switch (assertCostWithinLimit(icp_e8s)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };

    var charged = false;
    let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };

    if (icp_e8s > 0) {
      switch (await chargeUser(caller, icp_e8s)) {
        case (#err(msg)) { return #err(msg) };
        case (#ok(_)) { charged := true };
      };
    };

    try {
      switch (findOwnerIndex(caller)) {
        case null { return #err("No seeds found for this user") };
        case (?idx) {
          let (owner, seeds) = seedsByOwnerV2[idx];
          var updated = Array.tabulateVar<Seed>(seeds.size(), func(i : Nat) : Seed { seeds[i] });
          var found = false;

          var i : Nat = 0;
          while (i < updated.size()) {
            if (sameName(updated[i].name, normalizedName)) {
              updated[i] := {
                name = updated[i].name;
                seed_cipher = updated[i].seed_cipher;
                seed_iv = updated[i].seed_iv;
                image_cipher = ?image_cipher;
                image_iv = ?image_iv;
              };
              found := true;
              i := updated.size();
            } else {
              i += 1;
            };
          };

          if (not found) {
            return #err("Seed not found: " # normalizedName);
          };

          let immutableUpdated = Array.freeze<Seed>(updated);

          let updatedOwners = Array.tabulate<(Principal, [Seed])>(
            seedsByOwnerV2.size(),
            func(j : Nat) : (Principal, [Seed]) {
              if (j == idx) {
                (owner, immutableUpdated)
              } else {
                seedsByOwnerV2[j]
              }
            },
          );
          seedsByOwnerV2 := updatedOwners;
        };
      };

      if (icp_e8s > 0) {
        ignore await convertToCycles(amountToConvert);
      };
      audit("Added image to seed " # normalizedName, caller);
      #ok(());
    } catch (e) {
      if (charged) {
        await refundUser(caller, icp_e8s, "add image: " # Error.message(e));
      };
      #err("Failed to save image. Please try again.");
    };
  };

  public shared ({ caller }) func get_seed_cipher(name : Text) : async Result.Result<(Blob, Blob), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        var found : ?(Blob, Blob) = null;
        label search for (s in Array.vals(seeds)) {
          if (sameName(s.name, normalizedName)) {
            found := ?(s.seed_cipher, s.seed_iv);
            break search;
          };
        };
        switch (found) {
          case null { #err("Seed not found: " # normalizedName) };
          case (?pair) {
            let { icp_e8s } = await estimate_cost("decrypt", 1);
            switch (assertCostWithinLimit(icp_e8s)) {
              case (#err(msg)) { return #err(msg) };
              case (#ok(())) {};
            };
            var charged = false;
            if (icp_e8s > 0) {
              switch (await chargeUser(caller, icp_e8s)) {
                case (#err(msg)) { return #err(msg) };
                case (#ok(_)) { charged := true };
              };
            };

            try {
              if (icp_e8s > 0) {
                let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
                ignore await convertToCycles(amountToConvert);
              };
              audit("Retrieved cipher only for seed " # normalizedName, caller);
              #ok(pair);
            } catch (e) {
              if (charged) {
                await refundUser(caller, icp_e8s, "decrypt seed: " # Error.message(e));
              };
              #err("Failed to retrieve seed");
            };
          };
        };
      };
    };
  };

  public shared ({ caller }) func get_seed_cipher_and_key(
    name : Text,
    transport_public_key : Blob,
  ) : async Result.Result<(Blob, Blob, Blob), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        var found : ?(Blob, Blob) = null;
        label search for (s in Array.vals(seeds)) {
          if (sameName(s.name, normalizedName)) {
            found := ?(s.seed_cipher, s.seed_iv);
            break search;
          };
        };

        switch (found) {
          case null { #err("Seed not found: " # normalizedName) };
          case (?pair) {
            let decryptCost = await estimate_cost("decrypt", 1);
            let deriveCost = await estimate_cost("derive", 1);
            let total = decryptCost.icp_e8s + deriveCost.icp_e8s;
            switch (assertCostWithinLimit(total)) {
              case (#err(msg)) { return #err(msg) };
              case (#ok(())) {};
            };
            var charged = false;

            if (total > 0) {
              switch (await chargeUser(caller, total)) {
                case (#err(msg)) { return #err(msg) };
                case (#ok(_)) { charged := true };
              };
            };

            try {
              let input : Blob = Text.encodeUtf8(normalizedName);
              let { encrypted_key } = await (with cycles = 26_153_846_153) IC.vetkd_derive_key({
                input;
                context = context(caller);
                key_id = keyId();
                transport_public_key;
              });

              if (total > 0) {
                let amountToConvert = if (total > ICP_TO_CYCLES_BUFFER_E8S) { total - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
                ignore await convertToCycles(amountToConvert);
              };

              let (cipher, iv) = pair;
              audit("Retrieved cipher and vetKD key for seed " # normalizedName, caller);
              #ok((cipher, iv, encrypted_key));
            } catch (e) {
              if (charged) {
                await refundUser(caller, total, "decrypt and derive: " # Error.message(e));
              };
              #err("Failed to retrieve seed");
            };
          };
        };
      };
    };
  };

  public shared ({ caller }) func get_image_cipher(name : Text) : async Result.Result<(Blob, Blob), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        var found : ?Seed = null;
        label search for (s in Array.vals(seeds)) {
          if (sameName(s.name, normalizedName)) {
            found := ?s;
            break search;
          };
        };

        switch (found) {
          case null { #err("Seed not found: " # normalizedName) };
          case (?seed) {
            switch (seed.image_cipher, seed.image_iv) {
              case (?cipher, ?ivVal) {
                let { icp_e8s } = await estimate_cost("decrypt", 1);
                switch (assertCostWithinLimit(icp_e8s)) {
                  case (#err(msg)) { return #err(msg) };
                  case (#ok(())) {};
                };

                var charged = false;
                if (icp_e8s > 0) {
                  switch (await chargeUser(caller, icp_e8s)) {
                    case (#err(msg)) { return #err(msg) };
                    case (#ok(_)) { charged := true };
                  };
                };

                if (icp_e8s > 0) {
                  let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
                  ignore await convertToCycles(amountToConvert);
                };

                audit("Retrieved encrypted image for seed " # normalizedName, caller);
                #ok((cipher, ivVal));
              };
              case _ { #err("No image found for this seed") };
            };
          };
        };
      };
    };
  };

  public shared ({ caller }) func get_image_cipher_and_key(
    name : Text,
    transport_public_key : Blob,
  ) : async Result.Result<(Blob, Blob, Blob), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        var found : ?Seed = null;
        label search for (s in Array.vals(seeds)) {
          if (sameName(s.name, normalizedName)) {
            found := ?s;
            break search;
          };
        };

        switch (found) {
          case null { #err("Seed not found: " # normalizedName) };
          case (?seed) {
            switch (seed.image_cipher, seed.image_iv) {
              case (?cipher, ?ivVal) {
                let decryptCost = await estimate_cost("decrypt", 1);
                let deriveCost = await estimate_cost("derive", 1);
                let total = decryptCost.icp_e8s + deriveCost.icp_e8s;
                switch (assertCostWithinLimit(total)) { case (#err(msg)) { return #err(msg) }; case (#ok(())) {} };

                var charged = false;
                if (total > 0) {
                  switch (await chargeUser(caller, total)) {
                    case (#err(msg)) { return #err(msg) };
                    case (#ok(_)) { charged := true };
                  };
                };

                try {
                  let input : Blob = Text.encodeUtf8(normalizedName);
                  let { encrypted_key } = await (with cycles = 26_153_846_153) IC.vetkd_derive_key({
                    input;
                    context = context(caller);
                    key_id = keyId();
                    transport_public_key;
                  });

                  if (total > 0) {
                    let amountToConvert = if (total > ICP_TO_CYCLES_BUFFER_E8S) { total - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
                    ignore await convertToCycles(amountToConvert);
                  };

                  audit("Retrieved image cipher and vetKD key for seed " # normalizedName, caller);
                  #ok((cipher, ivVal, encrypted_key));
                } catch (e) {
                  if (charged) {
                    await refundUser(caller, total, "decrypt and derive image: " # Error.message(e));
                  };
                  #err("Failed to retrieve image");
                };
              };
              case _ { #err("No image found for this seed") };
            };
          };
        };
      };
    };
  };

  // Retrieve the seed cipher, optional image cipher, and vetKD-derived key together so the
  // frontend can decrypt all attachments in a single paid call.
  public shared ({ caller }) func get_ciphers_and_key(
    name : Text,
    transport_public_key : Blob,
  ) : async Result.Result<(Blob, Blob, ?Blob, ?Blob, Blob), Text> {
    ensureSeedsMigrated();
    let normalizedName = switch (validateRequestedName(name)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(n)) { n };
    };

    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };

    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwnerV2[idx];
        var found : ?Seed = null;
        label search for (s in Array.vals(seeds)) {
          if (sameName(s.name, normalizedName)) {
            found := ?s;
            break search;
          };
        };

        switch (found) {
          case null { #err("Seed not found: " # normalizedName) };
          case (?seed) {
            var decryptOps : Nat = 1;
            switch (seed.image_cipher) {
              case (?_) { decryptOps += 1 };
              case null {};
            };

            let decryptCost = await estimate_cost("decrypt", decryptOps);
            let deriveCost = await estimate_cost("derive", 1);
            let total = decryptCost.icp_e8s + deriveCost.icp_e8s;
            switch (assertCostWithinLimit(total)) {
              case (#err(msg)) { return #err(msg) };
              case (#ok(())) {};
            };

            var charged = false;
            if (total > 0) {
              switch (await chargeUser(caller, total)) {
                case (#err(msg)) { return #err(msg) };
                case (#ok(_)) { charged := true };
              };
            };

            try {
              let input : Blob = Text.encodeUtf8(normalizedName);
              let { encrypted_key } = await (with cycles = DERIVE_CYCLE_COST) IC.vetkd_derive_key({
                input;
                context = context(caller);
                key_id = keyId();
                transport_public_key;
              });

              if (total > 0) {
                let amountToConvert = if (total > ICP_TO_CYCLES_BUFFER_E8S) { total - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
                ignore await convertToCycles(amountToConvert);
              };

              audit("Retrieved ciphers and vetKD key for seed " # normalizedName, caller);
              #ok((seed.seed_cipher, seed.seed_iv, seed.image_cipher, seed.image_iv, encrypted_key));
            } catch (e) {
              if (charged) {
                await refundUser(caller, total, "decrypt seed and attachments: " # Error.message(e));
              };
              #err("Failed to retrieve data");
            };
          };
        };
      };
    };
  };

  public query func canister_cycles() : async Nat {
    ExperimentalCycles.balance()
  };

  public query func pricing_status() : async {
    last_rate : Nat;
    last_refresh_nanoseconds : Int;
    fallback_used : Bool;
  } {
    {
      last_rate = last_xdr_per_icp_rate;
      last_refresh_nanoseconds = last_xdr_refresh_ns;
      fallback_used = last_pricing_fallback_used;
    }
  };

  // Provide callers with a short rolling audit history of their own actions.
  public query ({ caller }) func get_audit_log() : async [(Int, Text)] {
    switch (Trie.find(auditLogs, callerKey(caller), Principal.equal)) {
      case (?entries) { entries };
      case null { [] };
    }
  };

  // Allow authenticated users to trigger conversion of accumulated ICP in the default account into cycles
  // without blocking user-facing calls.
  public shared ({ caller }) func convert_collected_icp() : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) {
      return #err("Anonymous callers cannot convert ICP");
    };

    let selfPrincipal = Principal.fromActor(Self);
    let defaultAccount : Account = { owner = selfPrincipal; subaccount = null };
    let balance = try {
      await ledger().icrc1_balance_of(defaultAccount)
    } catch (e) {
      return #err("Ledger unavailable: " # Error.message(e));
    };

    if (balance <= ICP_TRANSFER_FEE) {
      return #err("Insufficient ICP to convert after reserving transfer fee");
    };

    await convertToCycles(balance - ICP_TRANSFER_FEE);
  };

  system func preupgrade() {
    ensureSeedsMigrated();
  };
};
