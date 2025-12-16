import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type Result = { 'ok' : bigint } |
  { 'err' : string };
export type Result_1 = {
    'ok' : [Uint8Array | number[], Uint8Array | number[], Uint8Array | number[]]
  } |
  { 'err' : string };
export type Result_2 = {
    'ok' : [Uint8Array | number[], Uint8Array | number[]]
  } |
  { 'err' : string };
export type Result_3 = { 'ok' : null } |
  { 'err' : string };
export interface _SERVICE {
  'add_seed' : ActorMethod<
    [string, Uint8Array | number[], Uint8Array | number[]],
    Result_3
  >,
  'canister_cycles' : ActorMethod<[], bigint>,
  'convert_collected_icp' : ActorMethod<[], Result_3>,
  'delete_seed' : ActorMethod<[string], Result_3>,
  'encrypted_symmetric_key_for_seed' : ActorMethod<
    [string, Uint8Array | number[]],
    Uint8Array | number[]
  >,
  'estimate_cost' : ActorMethod<
    [string, bigint],
    { 'icp_e8s' : bigint, 'fallback_used' : boolean, 'cycles' : bigint }
  >,
  'get_account_details' : ActorMethod<
    [],
    {
      'balance' : bigint,
      'owner' : string,
      'subaccount' : Uint8Array | number[],
      'canister' : string,
    }
  >,
  'get_seed_cipher' : ActorMethod<[string], Result_2>,
  'get_seed_cipher_and_key' : ActorMethod<
    [string, Uint8Array | number[]],
    Result_1
  >,
  'get_seed_names' : ActorMethod<[], Array<string>>,
  'pricing_status' : ActorMethod<
    [],
    {
      'fallback_used' : boolean,
      'last_rate' : bigint,
      'last_refresh_nanoseconds' : bigint,
    }
  >,
  'public_key' : ActorMethod<[], Uint8Array | number[]>,
  'seed_count' : ActorMethod<[], bigint>,
  'transfer_icp' : ActorMethod<[string, bigint], Result>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
