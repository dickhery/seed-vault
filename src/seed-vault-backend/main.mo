import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Char "mo:base/Char";
import Error "mo:base/Error";
import Debug "mo:base/Debug";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Nat "mo:base/Nat";
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

  // Legacy ICP ledger transfer (for 64-char account identifiers).
  type LegacyTransferError = {
    #BadFee : { expected_fee : { e8s : Nat64 } };
    #InsufficientFunds : { balance : { e8s : Nat64 } };
    #TxTooOld : { allowed_window_nanos : Nat64 };
    #TxCreatedInFuture;
    #TxDuplicate : { duplicate_of : Nat64 };
  };

  type LegacyTransferArgs = {
    memo : Nat64;
    amount : { e8s : Nat64 };
    fee : { e8s : Nat64 };
    to : Blob;
    from_subaccount : ?Blob;
    created_at_time : ?{ timestamp_nanos : Nat64 };
  };

  type LegacyTransferResult = { #Ok : Nat64; #Err : LegacyTransferError };

  type Ledger = actor {
    icrc1_balance_of : Account -> async Nat;
    icrc1_transfer : TransferArg -> async TransferResult;
    transfer : LegacyTransferArgs -> async LegacyTransferResult;
  };

  // XRC exchange rate types. Motoko reserves `class` as a keyword; the trailing
  // underscore keeps the Motoko identifier valid while Candid still serializes
  // the field name as `class` (the standard keyword-escape mapping in Motoko).
  type XrcAsset = { symbol : Text; class_ : { #Cryptocurrency; #FiatCurrency } };
  type XrcGetExchangeRateRequest = { base_asset : XrcAsset; quote_asset : XrcAsset; timestamp : ?Nat64 };
  type XrcGetExchangeRateResult = { #Ok : { rate : Nat64 }; #Err : Text };
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
    #FailedToWithdraw : { rejection_code : {#NoError; #CanisterError; #SysTransient; #DestinationInvalid; #Unknown; #SysFatal; #CanisterReject}; rejection_reason : Text; fee_block : ?Nat };
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
  // 420 UTF-8 characters can expand to ~1680 bytes in the worst case; AES-GCM adds
  // a 16-byte tag, so we reject ciphertexts above 2 KB to enforce the character limit
  // even if the frontend is bypassed.
  let MAX_SEED_CIPHER_BYTES : Nat = 2_048;
  let MAX_SEED_NAME_CHARS : Nat = 100;
  let MAX_SEEDS_PER_USER : Nat = 50;
  let ENCRYPT_CYCLE_COST : Nat = 0;
  let DECRYPT_CYCLE_COST : Nat = 0;
  let PRICING_REFRESH_INTERVAL_NS : Int = 300_000_000_000; // 5 minutes
  let FALLBACK_RETRY_INTERVAL_NS : Int = 60_000_000_000; // 1 minute between fallback retries
  // The XRC requires at least 1B cycles to be attached to each request. Keep a
  // small buffer above that to avoid transient `NotEnoughCycles` rejections on
  // saturated replicas. This improves the likelihood of live pricing succeeding
  // across environments, including mobile browsers that rely on the same
  // backend canister state.
  let XRC_CALL_CYCLES : Nat = 1_100_000_000;
  // Match the cycles attached in vetkd_derive_key so pricing reflects the
  // actual derivation cost instead of an inflated estimate.
  let DERIVE_CYCLE_COST : Nat = 26_153_846_153;
  // Withdraw fee on cycles ledger (100M cycles).
  let CYCLES_WITHDRAW_FEE : Nat = 100_000_000;
  // Add a small buffer so we can pay the fee to convert collected ICP into cycles.
  let ICP_TO_CYCLES_BUFFER_E8S : Nat = ICP_TRANSFER_FEE;
  let CMC_PRINCIPAL : Principal = Principal.fromText("rkp4c-7iaaa-aaaaa-aaaca-cai");
  let MINT_MEMO : Blob = Blob.fromArray([77, 73, 78, 84, 0, 0, 0, 0]); // "MINT\00\00\00\00"
  let CMC : CyclesMintingCanister = actor (Principal.toText(CMC_PRINCIPAL));

  // Stable-friendly storage mapping owner -> list of (seed name, cipher, iv)
  stable var seedsByOwner : [(Principal, [(Text, Blob, Blob)])] = [];
  // Remember the last successful XRC XDR/ICP rate so pricing stays fresh even if a later call fails.
  stable var last_xdr_per_icp_rate : Nat = 0;
  // Track when pricing was last refreshed so the frontend can present a meaningful timestamp and we can
  // throttle exchange-rate lookups to avoid unnecessary XRC calls.
  stable var last_xdr_refresh_ns : Int = 0;
  // Whether the most recent pricing refresh had to rely on the fallback rate instead of a live XRC response.
  stable var last_pricing_fallback_used : Bool = false;
  // Track per-user operation counts for rate limiting.
  stable var userOps : Trie.Trie<Principal, (Nat, Int)> = Trie.empty();

  let RATE_LIMIT : Nat = 50; // operations per reset interval
  let RESET_INTERVAL : Int = 3_600_000_000_000; // 1 hour in nanoseconds

  private func findOwnerIndex(owner : Principal) : ?Nat {
    var i : Nat = 0;
    while (i < seedsByOwner.size()) {
      let (p, _) = seedsByOwner[i];
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

  private func hasSeedName(seeds : [(Text, Blob, Blob)], name : Text) : Bool {
    var i : Nat = 0;
    while (i < seeds.size()) {
      let (n, _, _) = seeds[i];
      if (sameName(n, name)) {
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

  private func checkRateLimit(caller : Principal) : Result.Result<(), Text> {
    let now = Time.now();
    let key = callerKey(caller);

    switch (Trie.find(userOps, key, Principal.equal)) {
      case (? (count, lastReset)) {
        if (now - lastReset >= RESET_INTERVAL) {
          let (updatedTrie, _) = Trie.put(userOps, key, Principal.equal, (1, now));
          userOps := updatedTrie;
          #ok(())
        } else if (count >= RATE_LIMIT) {
          #err("Rate limit exceeded. Try again later.")
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

  private func hexNibble(c : Char) : ?Nat8 {
    let code = Char.toNat32(c);
    if (code >= 48 and code <= 57) {
      ?Nat8.fromNat(Nat32.toNat(code - 48))
    } else if (code >= 65 and code <= 70) {
      ?Nat8.fromNat(Nat32.toNat(code - 55))
    } else if (code >= 97 and code <= 102) {
      ?Nat8.fromNat(Nat32.toNat(code - 87))
    } else {
      null
    }
  };

  private func hexToBytes(hex : Text) : ?[Nat8] {
    let chars = Text.toArray(hex);
    if (chars.size() != 64) {
      return null;
    };

    let nibbles = Array.tabulate<Nat8>(chars.size(), func(i : Nat) : Nat8 {
      switch (hexNibble(chars[i])) {
        case null { 255 };
        case (?v) { v };
      }
    });

    var invalid = false;
    var i : Nat = 0;
    while (i < nibbles.size()) {
      if (nibbles[i] == 255) { invalid := true };
      i += 1;
    };
    if (invalid) {
      return null;
    };

    ?Array.tabulate<Nat8>(32, func(j : Nat) : Nat8 {
      let hi = nibbles[j * 2];
      let lo = nibbles[j * 2 + 1];
      (hi << 4) + lo
    })
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
      base_asset = { symbol = "ICP"; class_ = #Cryptocurrency };
      quote_asset = { symbol = "XDR"; class_ = #FiatCurrency };
      timestamp = null;
    };
    let fallback_rate : Nat = 2_000_000_000; // Fallback XDR per ICP *1e9 (≈2 XDR per ICP)
    var balance = ExperimentalCycles.balance();
    var fallbackUsed = false;

    // If we're short on cycles for an XRC call but have ICP sitting in the default
    // account, opportunistically convert a portion so we can avoid stale pricing.
    if (balance < XRC_CALL_CYCLES) {
      let selfPrincipal = Principal.fromActor(Self);
      let defaultAccount : Account = { owner = selfPrincipal; subaccount = null };
      let icpBalance = try {
        await ledger().icrc1_balance_of(defaultAccount)
      } catch (e) {
        Debug.print("Unable to check ICP balance for auto top-up: " # Error.message(e));
        0
      };

      // Leave the transfer fee untouched so we can pay for the conversion itself.
      if (icpBalance > ICP_TO_CYCLES_BUFFER_E8S) {
        let convertible = icpBalance - ICP_TO_CYCLES_BUFFER_E8S;
        switch (await convertToCycles(convertible)) {
          case (#ok(())) {
            balance := ExperimentalCycles.balance();
          };
          case (#err(msg)) {
            Debug.print("Auto-convert for XRC pricing failed: " # msg);
          };
        };
      };
    };

    let to_add = Nat.min(balance, XRC_CALL_CYCLES);
    if (to_add > 0) {
      ExperimentalCycles.add(to_add);
    } else {
      fallbackUsed := true;
    };

    let rateResult : XrcGetExchangeRateResult = if (to_add > 0) {
      try {
        await XRC.get_exchange_rate(request)
      } catch (e) {
        Debug.print("XRC call failed: " # Error.message(e));
        fallbackUsed := true;
        #Err("xrc unavailable")
      }
    } else { #Err("insufficient cycles to call xrc") };

    let rateNat : Nat = switch (rateResult) {
      case (#Ok({ rate })) {
        let r = Nat64.toNat(rate);
        last_xdr_per_icp_rate := r;
        last_pricing_fallback_used := false;
        last_xdr_refresh_ns := now;
        Debug.print("XRC rate (XDR per ICP *1e9) used: " # Nat.toText(r));
        r
      };
      case (#Err(_)) {
        Debug.print("Using cached/fallback XDR rate. Cached: " # Nat.toText(last_xdr_per_icp_rate));
        fallbackUsed := true;
        let rateChoice = if (last_xdr_per_icp_rate > 0) { last_xdr_per_icp_rate } else { fallback_rate };
        if (last_xdr_per_icp_rate == 0) {
          last_xdr_per_icp_rate := rateChoice;
        };
        last_pricing_fallback_used := true;
        last_xdr_refresh_ns := now;
        rateChoice
      };
    };
    { rate = if (rateNat == 0) { 1 } else { rateNat }; fallback_used = fallbackUsed };
  };

  private func cyclesToIcp(cycles : Nat) : async { icp_e8s : Nat; fallback_used : Bool } {
    if (cycles == 0) {
      return { icp_e8s = 0; fallback_used = false };
    };

    let { rate; fallback_used } = await refreshXdrRate();
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

          if (mintedBalance <= CYCLES_WITHDRAW_FEE) {
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
        case (#Ok(_)) {};
        case (#Err(err)) {
          Debug.print("Refund failed (" # context # "): " # debug_show(err));
        };
      };
    } catch (e) {
      Debug.print("Refund transfer error (" # context # "): " # Error.message(e));
    };
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

    // Prefer treating the input as a legacy account identifier first to avoid trapping on invalid principals.
    let accountIdBytes = hexToBytes(Text.toUppercase(to_text));
    switch (accountIdBytes) {
      case (?toBytes) {
        let required = amount + ICP_TRANSFER_FEE * 2;
        if (balance < required) {
          return #err("Insufficient balance to cover amount and fees");
        };

        let defaultAccount : Account = { owner = Principal.fromActor(Self); subaccount = null };
        let moveAmount = amount + ICP_TRANSFER_FEE;

        let internalTransfer = try {
          await ledger().icrc1_transfer({
            from_subaccount = ?callerSub;
            to = defaultAccount;
            amount = moveAmount;
            fee = ?ICP_TRANSFER_FEE;
            memo = null;
            created_at_time = null;
          })
        } catch (e) {
          return #err("Internal transfer failed: " # Error.message(e));
        };

        switch (internalTransfer) {
          case (#Err(#InsufficientFunds)) { return #err("Internal transfer: insufficient funds") };
          case (#Err(#BadFee({ expected_fee }))) {
            return #err("Internal transfer: incorrect fee. Expected " # Nat.toText(expected_fee))
          };
          case (#Err(#GenericError({ message }))) { return #err("Internal transfer error: " # message) };
          case (#Ok(_)) {};
        };

        let legacyArgs : LegacyTransferArgs = {
          memo = 0;
          amount = { e8s = Nat64.fromNat(amount) };
          fee = { e8s = Nat64.fromNat(ICP_TRANSFER_FEE) };
          to = Blob.fromArray(toBytes);
          from_subaccount = null;
          created_at_time = null;
        };

        let legacyResult = try { await ledger().transfer(legacyArgs) } catch (e) {
          return #err("Legacy transfer failed: " # Error.message(e));
        };

        switch (legacyResult) {
          case (#Ok(block)) { #ok(Nat64.toNat(block)) };
          case (#Err(err)) { #err(debug_show(err)) };
        };
      };
      case null {
        let principalRecipient : ?Principal = try {
          ?Principal.fromText(to_text)
        } catch (_) { null };

        switch (principalRecipient) {
          case null { return #err("Invalid recipient: must be a principal or 64-character account identifier") };
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
    };
  };

  public shared ({ caller }) func estimate_cost(operation : Text, count : Nat) : async {
    cycles : Nat;
    icp_e8s : Nat;
    fallback_used : Bool;
  } {
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return { cycles = 0; icp_e8s = 0; fallback_used = true } };
      case (#ok(())) {};
    };

    let cycles = operationCycles(operation, count);
    let { icp_e8s; fallback_used } = await cyclesToIcp(cycles);
    let capped = icp_e8s;
    var fallback = fallback_used;
    if (icp_e8s > MAX_OPERATION_COST_E8S) {
      capped := MAX_OPERATION_COST_E8S;
      fallback := true;
    };
    { cycles; icp_e8s = capped; fallback_used = fallback };
  };

  public query ({ caller }) func seed_count() : async Nat {
    switch (findOwnerIndex(caller)) {
      case (?idx) { let (_, seeds) = seedsByOwner[idx]; seeds.size() };
      case null { 0 };
    };
  };

  public query ({ caller }) func get_seed_names() : async [Text] {
    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        Array.map<(Text, Blob, Blob), Text>(seeds, func((n, _, _)) : Text { n });
      };
      case null { [] };
    };
  };

  public shared ({ caller }) func encrypted_symmetric_key_for_seed(name : Text, transport_public_key : Blob) : async Blob {
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
      let input : Blob = Text.encodeUtf8(name);
      let { encrypted_key } = await (with cycles = 26_153_846_153) IC.vetkd_derive_key({
        input;
        context = context(caller);
        key_id = keyId();
        transport_public_key;
      });

      let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
      ignore await convertToCycles(amountToConvert);
      encrypted_key;
    } catch (e) {
      if (charged) {
        await refundUser(caller, icp_e8s, "derive key: " # Error.message(e));
      };
      throw Error.reject("Failed to derive encrypted key");
    };
  };

  public shared ({ caller }) func add_seed(name : Text, cipher : Blob, iv : Blob) : async Result.Result<(), Text> {
    let normalizedName = normalizeName(name);
    Debug.print("Add seed requested by " # Principal.toText(caller) # " for name '" # normalizedName # "'");

    if (Text.size(normalizedName) == 0) {
      return #err("Name cannot be empty");
    };
    if (Text.size(normalizedName) > MAX_SEED_NAME_CHARS) {
      return #err("Name too long. Maximum 100 characters.");
    };
    if (not isValidSeedName(name)) {
      return #err("Invalid characters in name. Allowed: letters, digits, spaces, hyphens, underscores.");
    };
    if (Blob.toArray(cipher).size() == 0) {
      return #err("Ciphertext cannot be empty");
    };
    if (Blob.toArray(cipher).size() > MAX_SEED_CIPHER_BYTES) {
      return #err("Seed phrase too long. Limit is 420 characters.");
    };

    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
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
        case (?idx) {
          let (_, seeds) = seedsByOwner[idx];
          let updatedSeeds = Array.append<(Text, Blob, Blob)>(seeds, [(normalizedName, cipher, iv)]);
          let updatedOwners = Array.tabulate<(Principal, [(Text, Blob, Blob)])>(
            seedsByOwner.size(),
            func(j : Nat) : (Principal, [(Text, Blob, Blob)]) {
              if (j == idx) {
                (caller, updatedSeeds)
              } else {
                seedsByOwner[j]
              }
            },
          );
          seedsByOwner := updatedOwners;
        };
        case null {
          seedsByOwner := Array.append<(Principal, [(Text, Blob, Blob)])>(seedsByOwner, [(caller, [(normalizedName, cipher, iv)])]);
        };
      };

      if (icp_e8s > 0) {
        ignore await convertToCycles(amountToConvert);
      };
      #ok(());
    } catch (e) {
      if (charged) {
        await refundUser(caller, icp_e8s, "add seed: " # Error.message(e));
      };
      #err("Failed to save seed. Please try again.");
    };
  };

  public shared ({ caller }) func delete_seed(name : Text) : async Result.Result<(), Text> {
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    Debug.print("Delete seed requested by " # Principal.toText(caller) # " for name '" # name # "'");

    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (owner, seeds) = seedsByOwner[idx];
        let filtered = Array.filter<(Text, Blob, Blob)>(seeds, func((n, _, _)) : Bool { not sameName(n, name) });
        if (filtered.size() == seeds.size()) {
          return #err("Seed not found: " # name);
        };

        let updatedOwners = Array.tabulate<(Principal, [(Text, Blob, Blob)])>(
          seedsByOwner.size(),
          func(j : Nat) : (Principal, [(Text, Blob, Blob)]) {
            if (j == idx) {
              (owner, filtered)
            } else {
              seedsByOwner[j]
            }
          },
        );
        seedsByOwner := updatedOwners;
        #ok(());
      };
    };
  };

  public shared ({ caller }) func get_seed_cipher(name : Text) : async Result.Result<(Blob, Blob), Text> {
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    Debug.print("Cipher fetch requested by " # Principal.toText(caller) # " for name '" # name # "'");

    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        var found : ?(Blob, Blob) = null;
        label search for ((n, c, ivVal) in Array.vals(seeds)) {
          if (sameName(n, name)) {
            found := ?(c, ivVal);
            break search;
          };
        };
        switch (found) {
          case null { #err("Seed not found: " # name) };
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
    switch (checkRateLimit(caller)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    Debug.print("Decrypt+derive requested by " # Principal.toText(caller) # " for name '" # name # "'");

    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        var found : ?(Blob, Blob) = null;
        label search for ((n, c, ivVal) in Array.vals(seeds)) {
          if (sameName(n, name)) {
            found := ?(c, ivVal);
            break search;
          };
        };

        switch (found) {
          case null { #err("Seed not found: " # name) };
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
              let input : Blob = Text.encodeUtf8(name);
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
};
