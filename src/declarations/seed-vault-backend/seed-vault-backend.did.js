export const idlFactory = ({ IDL }) => {
  const Result_3 = IDL.Variant({ 'ok' : IDL.Null, 'err' : IDL.Text });
  const Result_2 = IDL.Variant({
    'ok' : IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8)),
    'err' : IDL.Text,
  });
  const Result_1 = IDL.Variant({
    'ok' : IDL.Tuple(IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8)),
    'err' : IDL.Text,
  });
  const Result = IDL.Variant({ 'ok' : IDL.Nat, 'err' : IDL.Text });
  const Result_4 = IDL.Variant({
    'ok' : IDL.Tuple(
      IDL.Vec(IDL.Nat8),
      IDL.Vec(IDL.Nat8),
      IDL.Opt(IDL.Vec(IDL.Nat8)),
      IDL.Opt(IDL.Vec(IDL.Nat8)),
    ),
    'err' : IDL.Text,
  });
  const Result_5 = IDL.Variant({
    'ok' : IDL.Tuple(
      IDL.Vec(IDL.Nat8),
      IDL.Vec(IDL.Nat8),
      IDL.Opt(IDL.Vec(IDL.Nat8)),
      IDL.Opt(IDL.Vec(IDL.Nat8)),
      IDL.Vec(IDL.Nat8),
    ),
    'err' : IDL.Text,
  });
  return IDL.Service({
    'add_image' : IDL.Func([
        IDL.Text,
        IDL.Vec(IDL.Nat8),
        IDL.Vec(IDL.Nat8),
      ],
      [Result_3],
      [],
    ),
    'add_seed' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8), IDL.Opt(IDL.Vec(IDL.Nat8)), IDL.Opt(IDL.Vec(IDL.Nat8))],
        [Result_3],
        [],
      ),
    'canister_cycles' : IDL.Func([], [IDL.Nat], ['query']),
    'convert_collected_icp' : IDL.Func([], [Result_3], []),
    'delete_seed' : IDL.Func([IDL.Text], [Result_3], []),
    'encrypted_symmetric_key_for_seed' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8)],
        [IDL.Vec(IDL.Nat8)],
        [],
      ),
    'estimate_cost' : IDL.Func(
        [IDL.Text, IDL.Nat],
        [
          IDL.Record({
            'icp_e8s' : IDL.Nat,
            'fallback_used' : IDL.Bool,
            'cycles' : IDL.Nat,
          }),
        ],
        [],
      ),
    'get_account_details' : IDL.Func(
        [],
        [
          IDL.Record({
            'balance' : IDL.Nat,
            'owner' : IDL.Text,
            'subaccount' : IDL.Vec(IDL.Nat8),
            'canister' : IDL.Text,
          }),
        ],
        [],
      ),
    'get_image_cipher' : IDL.Func([IDL.Text], [Result_2], []),
    'get_image_cipher_and_key' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8)],
        [Result_1],
        [],
      ),
    'get_seed_and_image_ciphers' : IDL.Func([IDL.Text], [Result_4], []),
    'get_seed_and_image_ciphers_and_key' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8)],
        [Result_5],
        [],
      ),
    'get_seed_cipher' : IDL.Func([IDL.Text], [Result_2], []),
    'get_seed_cipher_and_key' : IDL.Func(
        [IDL.Text, IDL.Vec(IDL.Nat8)],
        [Result_1],
        [],
      ),
    'get_seed_names' : IDL.Func(
        [],
        [IDL.Vec(IDL.Record({ name: IDL.Text, has_image: IDL.Bool }))],
        ['query'],
      ),
    'pricing_status' : IDL.Func(
        [],
        [
          IDL.Record({
            'fallback_used' : IDL.Bool,
            'last_rate' : IDL.Nat,
            'last_refresh_nanoseconds' : IDL.Int,
          }),
        ],
        ['query'],
      ),
    'public_key' : IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    'seed_count' : IDL.Func([], [IDL.Nat], ['query']),
    'transfer_icp' : IDL.Func([IDL.Text, IDL.Nat], [Result], []),
  });
};
export const init = ({ IDL }) => { return []; };
