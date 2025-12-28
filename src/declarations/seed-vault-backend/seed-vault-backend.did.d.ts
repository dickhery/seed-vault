import type { Principal } from '@dfinity/principal';
import type { IDL } from '@dfinity/candid';

export type Result = { ok: bigint } | { err: string };
export type Result_1 = { ok: [Uint8Array | number[], Uint8Array | number[], Uint8Array | number[]] } | { err: string };
export type Result_2 = { ok: [Uint8Array | number[], Uint8Array | number[]] } | { err: string };
export type Result_3 = { ok: null } | { err: string };
export type Result_4 = {
  ok: [Uint8Array | number[], Uint8Array | number[], [] | [Uint8Array | number[]], [] | [Uint8Array | number[]]];
} | { err: string };
export type Result_5 = {
  ok: [
    Uint8Array | number[],
    Uint8Array | number[],
    [] | [Uint8Array | number[]],
    [] | [Uint8Array | number[]],
    Uint8Array | number[],
  ];
} | { err: string };
export interface _SERVICE {
  add_image: (name: string, image_cipher: Uint8Array | number[], image_iv: Uint8Array | number[]) => Promise<Result_3>;
  add_seed: (
    name: string,
    cipher: Uint8Array | number[],
    iv: Uint8Array | number[],
    image_cipher: [] | [Uint8Array | number[]],
    image_iv: [] | [Uint8Array | number[]],
  ) => Promise<Result_3>;
  canister_cycles: () => Promise<bigint>;
  convert_collected_icp: () => Promise<Result_3>;
  delete_seed: (name: string) => Promise<Result_3>;
  encrypted_symmetric_key_for_seed: (name: string, transport_public_key: Uint8Array | number[]) => Promise<Uint8Array | number[]>;
  estimate_cost: (
    operation: string,
    count: bigint,
  ) => Promise<{ cycles: bigint; fallback_used: boolean; icp_e8s: bigint }>;
  get_account_details: () => Promise<{ balance: bigint; canister: string; owner: string; subaccount: Uint8Array | number[] }>;
  get_image_cipher: (name: string) => Promise<Result_2>;
  get_image_cipher_and_key: (name: string, transport_public_key: Uint8Array | number[]) => Promise<Result_1>;
  get_seed_and_image_ciphers: (name: string) => Promise<Result_4>;
  get_seed_and_image_ciphers_and_key: (
    name: string,
    transport_public_key: Uint8Array | number[],
  ) => Promise<Result_5>;
  get_seed_cipher: (name: string) => Promise<Result_2>;
  get_seed_cipher_and_key: (name: string, transport_public_key: Uint8Array | number[]) => Promise<Result_1>;
  get_seed_names: () => Promise<Array<{ has_image: boolean; name: string }>>;
  pricing_status: () => Promise<{ fallback_used: boolean; last_rate: bigint; last_refresh_nanoseconds: bigint | number }>;
  public_key: () => Promise<Uint8Array | number[]>;
  seed_count: () => Promise<bigint>;
  transfer_icp: (to_text: string, amount: bigint) => Promise<Result>;
}
export const idlFactory: ({ IDL }: { IDL: IDL }) => IDL.ServiceClass;
export const init: ({ IDL }: { IDL: IDL }) => IDL.FuncClass;
