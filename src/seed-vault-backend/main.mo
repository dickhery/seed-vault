import Array "mo:base/Array";
import Blob "mo:base/Blob";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Nat8 "mo:base/Nat8";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Text "mo:base/Text";

persistent actor {
  // Type definitions for vetKD interactions
  type VetKdKeyId = { curve : { #bls12_381_g2 }; name : Text };
  type VetKdPublicKeyArgs = { canister_id : ?Principal; context : Blob; key_id : VetKdKeyId };
  type VetKdDeriveKeyArgs = { input : Blob; context : Blob; key_id : VetKdKeyId; transport_public_key : Blob };
  type EncryptedKeyReply = { encrypted_key : Blob };
  type PublicKeyReply = { public_key : Blob };

  // Call the management canister directly for vetKD.
  type VetKdApi = actor {
    vetkd_public_key : VetKdPublicKeyArgs -> async PublicKeyReply;
    vetkd_derive_key : VetKdDeriveKeyArgs -> async EncryptedKeyReply;
  };

  let IC : VetKdApi = actor "aaaaa-aa";

  // Keep domain separator as a blob and convert to bytes when building the vetKD context.
  let DOMAIN_SEPARATOR : Blob = Text.encodeUtf8("seed-vault-app");

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

  public query ({ caller }) func get_my_seeds() : async [(Text, Blob, Blob)] {
    switch (findOwnerIndex(caller)) {
      case (?idx) {
        let (_, seeds) = seedsByOwner[idx];
        seeds;
      };
      case null { [] };
    }
  };
};
