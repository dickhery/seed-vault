import Array "mo:base/Array";
import Blob "mo:base/Blob";
import HashMap "mo:base/HashMap";
import Iter "mo:base/Iter";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";

// Entry stored per caller
public type Entry = {
  name : Text;
  ciphertext : Blob;
  createdAt : Nat64;
};

// Maximum allowed ciphertext size in bytes (1 MiB)
let maxCiphertextBytes : Nat = 1_048_576;

stable var storeEntries : [(Principal, [Entry])] = [];

var store = HashMap.HashMap<Principal, [Entry]>(10, Principal.equal, Principal.hash);

persistent actor {
  system func preupgrade() {
    storeEntries := Iter.toArray(store.entries());
  };

  system func postupgrade() {
    store := HashMap.fromIter<Principal, [Entry]>(storeEntries.vals(), 10, Principal.equal, Principal.hash);
  };

  public query func listEntries() : async [Entry] {
    switch (store.get(msg.caller)) {
      case (?entries) entries;
      case null [];
    };
  };

  public func addEntry(name : Text, ciphertext : Blob) : async Result.Result<(), Text> {
    if (Text.size(name) == 0) {
      return #err("Entry name cannot be empty.");
    };

    if (Blob.size(ciphertext) == 0) {
      return #err("Ciphertext cannot be empty.");
    };

    if (Blob.size(ciphertext) > maxCiphertextBytes) {
      return #err("Ciphertext exceeds maximum allowed size.");
    };

    let caller = msg.caller;
    let existing = switch (store.get(caller)) { case (?entries) entries; case null [] };
    let filtered = Iter.toArray(
      Iter.filter<Entry>(existing.vals(), func(e : Entry) : Bool { e.name != name })
    );

    let updated = Array.append<Entry>(filtered, [
      {
        name = name;
        ciphertext = ciphertext;
        createdAt = Time.now();
      },
    ]);

    store.put(caller, updated);
    #ok(());
  };

  public func deleteEntry(name : Text) : async Result.Result<Bool, Text> {
    if (Text.size(name) == 0) {
      return #err("Entry name cannot be empty.");
    };

    let caller = msg.caller;
    switch (store.get(caller)) {
      case null { #ok(false) };
      case (?entries) {
        let filtered = Iter.toArray(
          Iter.filter<Entry>(entries.vals(), func(e : Entry) : Bool { e.name != name })
        );
        if (Array.size(filtered) == Array.size(entries)) {
          return #ok(false);
        };
        store.put(caller, filtered);
        #ok(true);
      };
    };
  };
};
