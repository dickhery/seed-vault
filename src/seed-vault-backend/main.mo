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

actor {
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
  type XrcAsset = { symbol : Text; `class` : { #Cryptocurrency; #FiatCurrency } };
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

  private func cyclesToIcp(cycles : Nat) : async Nat {
    let request : XrcGetExchangeRateRequest = {
      base_asset = { symbol = "ICP"; `class` = #Cryptocurrency };
      quote_asset = { symbol = "XDR"; `class` = #FiatCurrency };
      timestamp = null;
    };
    let rateResult = try {
      await XRC.get_exchange_rate(request)
    } catch (e) {
      return (cycles * ICP_PER_XDR_FALLBACK) / CYCLES_PER_XDR;
    };
    let icpPerXdr : Nat = switch (rateResult) {
      case (#Ok({ rate })) { Nat64.toNat(rate) };
      case (#Err(_)) { ICP_PER_XDR_FALLBACK };
    };
    let numerator = cycles * icpPerXdr;
    let baseCost = if (CYCLES_PER_XDR == 0) { 0 } else { numerator / CYCLES_PER_XDR };
    baseCost;
  };

  private func operationCycles(operation : Text, count : Nat) : Nat {
    if (Text.equal(operation, "encrypt")) {
      ENCRYPT_CYCLE_COST * count
    } else if (Text.equal(operation, "decrypt")) {
      DECRYPT_CYCLE_COST * count
    } else {
      0
    };
  };

  private func chargeUser(caller : Principal, amount : Nat) : async Result.Result<Nat, Text> {
    let callerSub = subaccount(caller);
    let account : Account = { owner = Principal.fromActor(this); subaccount = ?callerSub };

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
        to = { owner = Principal.fromActor(this); subaccount = null };
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
    let account : Account = { owner = Principal.fromActor(this); subaccount = ?callerSub };
    let balance = try {
      await LEDGER.icrc1_balance_of(account)
    } catch (e) {
      0
    };
    {
      owner = Principal.toText(caller);
      canister = Principal.toText(Principal.fromActor(this));
      subaccount = callerSub;
      balance;
    };
  };

  public shared ({ caller }) func estimate_cost(operation : Text, count : Nat) : async {
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

  public shared ({ caller }) func encrypted_symmetric_key_for_seed(name : Text, transport_public_key : Blob) : async Blob {
    let input : Blob = Text.encodeUtf8(name);
    ExperimentalCycles.add<system>(26_153_846_153);
    let { encrypted_key } = await IC.vetkd_derive_key({
      input;
      context = context(caller);
      key_id = keyId();
      transport_public_key;
    });
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

  public shared ({ caller }) func get_my_seeds() : async Result.Result<[(Text, Blob, Blob)], Text> {
    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        if (seeds.size() == 0) {
          return #ok(seeds);
        };
        let { icp_e8s } = await estimate_cost("decrypt", seeds.size());
        switch (await chargeUser(caller, icp_e8s)) {
          case (#err(msg)) { return #err(msg) };
          case (#ok(_)) {};
        };
        #ok(seeds);
      };
      case null { #ok([]) };
    }
  };
};
