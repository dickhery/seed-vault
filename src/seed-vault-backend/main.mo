import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Error "mo:base/Error";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat64 "mo:base/Nat64";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Text "mo:base/Text";

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

  // XRC exchange rate types
  // Use `asset_class` to avoid the Motoko keyword `class`.
  type XrcAsset = { symbol : Text; asset_class : { #Cryptocurrency; #FiatCurrency } };
  type XrcGetExchangeRateRequest = { base_asset : XrcAsset; quote_asset : XrcAsset; timestamp : ?Nat64 };
  type XrcGetExchangeRateResult = { #Ok : { rate : Nat64 }; #Err : Text };
  type Xrc = actor {
    get_exchange_rate : XrcGetExchangeRateRequest -> async XrcGetExchangeRateResult;
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

  let IC : VetKdApi = actor "aaaaa-aa";
  let LEDGER : Ledger = actor "ryjl3-tyaaa-aaaaa-aaaba-cai";
  let XRC : Xrc = actor "uf6dk-hyaaa-aaaaq-qaaaq-cai";

  // Keep domain separator as a blob and convert to bytes when building the vetKD context.
  let DOMAIN_SEPARATOR : Blob = Text.encodeUtf8("seed-vault-app");

  let ICP_TRANSFER_FEE : Nat = 10_000;
  let CYCLES_PER_XDR : Nat = 1_000_000_000_000;
  let ICP_PER_XDR_FALLBACK : Nat = 50_000_000; // 0.5 ICP in e8s fallback
  let ENCRYPT_CYCLE_COST : Nat = 30_000_000_000;
  let DECRYPT_CYCLE_COST : Nat = 30_000_000_000;
  let DERIVE_CYCLE_COST : Nat = 30_000_000_000;
  // Add a small buffer so we can pay the fee to convert collected ICP into cycles.
  let ICP_TO_CYCLES_BUFFER_E8S : Nat = ICP_TRANSFER_FEE;
  let CMC_PRINCIPAL : Principal = Principal.fromText("rkp4c-7iaaa-aaaaa-aaaca-cai");
  let MINT_MEMO : Blob = Blob.fromArray([77, 73, 78, 84, 0, 0, 0, 0]); // "MINT\00\00\00\00"
  let CMC : CyclesMintingCanister = actor (Principal.toText(CMC_PRINCIPAL));

  // Stable-friendly storage mapping owner -> list of (seed name, cipher, iv)
  stable var seedsByOwner : [(Principal, [(Text, Blob, Blob)])] = [];

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

  private func hasSeedName(seeds : [(Text, Blob, Blob)], name : Text) : Bool {
    var i : Nat = 0;
    while (i < seeds.size()) {
      let (n, _, _) = seeds[i];
      if (Text.equal(n, name)) {
        return true;
      };
      i += 1;
    };
    false;
  };

  private func keyId() : VetKdKeyId {
    // Use the production key on mainnet; switch to "test_key_1" if you want cheaper testing.
    { curve = #bls12_381_g2; name = "key_1" };
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

  private func cyclesToIcp(cycles : Nat) : async Nat {
    let request : XrcGetExchangeRateRequest = {
      base_asset = { symbol = "ICP"; asset_class = #Cryptocurrency };
      quote_asset = { symbol = "XDR"; asset_class = #FiatCurrency };
      timestamp = null;
    };
    let fallback_rate : Nat = 2_000_000_000; // 0.5 ICP/XDR expressed as rate (XDR per ICP)*1e9 => 2e9
    let rateResult = try { await XRC.get_exchange_rate(request) } catch (_) { #Err("xrc unavailable") };
    let rateNat : Nat = switch (rateResult) {
      case (#Ok({ rate })) { Nat64.toNat(rate) };
      case (#Err(_)) { fallback_rate };
    };
    let effectiveRate = if (rateNat == 0) { 1 } else { rateNat };
    let numerator : Nat = cycles * 100_000;
    let baseCost = numerator / effectiveRate;
    baseCost + ICP_TO_CYCLES_BUFFER_E8S;
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

  // Convert collected ICP into cycles by sending ICP to the CMC and notifying it.
  private func convertToCycles(amount : Nat) : async Result.Result<(), Text> {
    if (amount == 0) {
      return #ok(());
    };

    let balanceBefore = ExperimentalCycles.balance();
    let selfPrincipal = Principal.fromActor(Self);
    let defaultAccount : Account = { owner = selfPrincipal; subaccount = null };
    let balance = try {
      await LEDGER.icrc1_balance_of(defaultAccount)
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
      await LEDGER.icrc1_transfer(transferArgs)
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
          let balanceAfter = ExperimentalCycles.balance();
          if (balanceAfter > balanceBefore) {
            #ok(())
          } else {
            #err("CMC notify succeeded but cycles balance did not increase")
          }
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
      await LEDGER.icrc1_balance_of(account)
    } catch (e) {
      return #err("Ledger unavailable: " # Error.message(e));
    };
    if (balance < amount + ICP_TRANSFER_FEE) {
      return #err("Insufficient balance. Please transfer more ICP to proceed.");
    };

    let transferResult = try {
      await LEDGER.icrc1_transfer({
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
      await LEDGER.icrc1_balance_of(account)
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

  public shared ({ caller = _ }) func estimate_cost(operation : Text, count : Nat) : async {
    cycles : Nat;
    icp_e8s : Nat;
  } {
    let cycles = operationCycles(operation, count);
    let icp_e8s = await cyclesToIcp(cycles);
    { cycles; icp_e8s };
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
    let { icp_e8s } = await estimate_cost("derive", 1);
    switch (await chargeUser(caller, icp_e8s)) {
      case (#err(msg)) { throw Error.reject(msg) };
      case (#ok(_)) {};
    };

    let input : Blob = Text.encodeUtf8(name);
    let { encrypted_key } = await (with cycles = 26_153_846_153) IC.vetkd_derive_key({
      input;
      context = context(caller);
      key_id = keyId();
      transport_public_key;
    });

    let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
    switch (await convertToCycles(amountToConvert)) {
      case (#err(msg)) { throw Error.reject(msg) };
      case (#ok(())) {};
    };
    encrypted_key;
  };

  public shared ({ caller }) func add_seed(name : Text, cipher : Blob, iv : Blob) : async Result.Result<(), Text> {
    if (Text.size(name) == 0) {
      return #err("Name cannot be empty");
    };
    if (Blob.toArray(cipher).size() == 0) {
      return #err("Ciphertext cannot be empty");
    };
    let { icp_e8s } = await estimate_cost("encrypt", 1);
    switch (await chargeUser(caller, icp_e8s)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(_)) {};
    };
    let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
    switch (await convertToCycles(amountToConvert)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };
    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        if (hasSeedName(seeds, name)) {
          return #err("Name already exists for this user");
        };
        let updatedSeeds = Array.append<(Text, Blob, Blob)>(seeds, [(name, cipher, iv)]);
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
        seedsByOwner := Array.append<(Principal, [(Text, Blob, Blob)])>(seedsByOwner, [(caller, [(name, cipher, iv)])]);
      };
    };
    #ok(());
  };

  public shared ({ caller }) func get_seed_cipher(name : Text) : async Result.Result<(Blob, Blob), Text> {
    let { icp_e8s } = await estimate_cost("decrypt", 1);
    switch (await chargeUser(caller, icp_e8s)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(_)) {};
    };
    let amountToConvert = if (icp_e8s > ICP_TO_CYCLES_BUFFER_E8S) { icp_e8s - ICP_TO_CYCLES_BUFFER_E8S } else { 0 };
    switch (await convertToCycles(amountToConvert)) {
      case (#err(msg)) { return #err(msg) };
      case (#ok(())) {};
    };

    switch (findOwnerIndex(caller)) {
      case null { #err("No seeds found for this user") };
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        var found : ?(Blob, Blob) = null;
        label search for ((n, c, ivVal) in Array.vals(seeds)) {
          if (Text.equal(n, name)) {
            found := ?(c, ivVal);
            break search;
          };
        };
        switch (found) {
          case null { #err("Seed not found: " # name) };
          case (?pair) { #ok(pair) };
        };
      };
    };
  };

  public query func canister_cycles() : async Nat {
    ExperimentalCycles.balance()
  };
};
