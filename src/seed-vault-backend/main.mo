import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Iter "mo:base/Iter";
import Map "mo:base/TrieMap";
import Nat8 "mo:base/Nat8";
import Option "mo:base/Option";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Text "mo:base/Text";
import ExperimentalCycles "mo:base/ExperimentalCycles";

actor {
  // Type definitions for vetKD interactions must live inside the actor to satisfy Motoko's actor file rules.
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

  transient let IC : VetKdApi = actor "aaaaa-aa";

  transient let DOMAIN_SEPARATOR : Blob = Blob.fromArray(Text.encodeUtf8("seed-vault-app"));
  stable var stableSeeds : [(Principal, [(Text, { cipher : Blob; iv : Blob })])] = [];

  transient let seedsByOwner = Map.TrieMap<Principal, Map.TrieMap<Text, { cipher : Blob; iv : Blob }>>(Principal.equal, Principal.hash);

  private func keyId() : VetKdKeyId {
    // Use the mainnet test key so deployments to the IC succeed. Switch to "key_1" for production traffic.
    { curve = #bls12_381_g2; name = "test_key_1" };
  };

  private func context(principal : Principal) : Blob {
    let principalBytes = Blob.toArray(Principal.toBlob(principal));
    let dom = Blob.toArray(DOMAIN_SEPARATOR);
    let size = Nat8.fromNat(principalBytes.size());
    let sizeArr : [Nat8] = [size];
    let withDomain = Array.append(sizeArr, dom);
    let flattened = Array.append(withDomain, principalBytes);
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
    let input = Blob.fromArray(Text.encodeUtf8(name));
    ExperimentalCycles.add<system>(10_000_000_000);
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
    let userSeeds = Option.get(seedsByOwner.get(caller), Map.TrieMap<Text, { cipher : Blob; iv : Blob }>(Text.equal, Text.hash));
    switch (userSeeds.get(name)) {
      case (?_) { return #err("Name already exists for this user"); };
      case (null) {};
    };
    userSeeds.put(name, { cipher; iv });
    seedsByOwner.put(caller, userSeeds);
    #ok(());
  };

  public query ({ caller }) func get_my_seeds() : async [(Text, Blob, Blob)] {
    switch (seedsByOwner.get(caller)) {
      case (null) { [] };
      case (?userSeeds) {
        Iter.toArray<(Text, Blob, Blob)>(Iter.map<(Text, { cipher : Blob; iv : Blob }), (Text, Blob, Blob)>(userSeeds.entries(), func((n, e)) {
          (n, e.cipher, e.iv)
        }));
      };
    };
  };

  system func preupgrade() {
    stableSeeds := Iter.toArray<(Principal, [(Text, { cipher : Blob; iv : Blob })])>(Iter.map<(Principal, Map.TrieMap<Text, { cipher : Blob; iv : Blob }>), (Principal, [(Text, { cipher : Blob; iv : Blob })])>(
      seedsByOwner.entries(),
      func((p, m)) {
        (p, Iter.toArray(m.entries()))
      }
    ));
  };

  system func postupgrade() {
    for ((p, entries) in stableSeeds.vals()) {
      let m = Map.TrieMap<Text, { cipher : Blob; iv : Blob }>(Text.equal, Text.hash);
      for ((n, e) in entries.vals()) {
        m.put(n, e);
      };
      seedsByOwner.put(p, m);
    };
    stableSeeds := [];
  };
};
