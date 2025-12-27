import type { IDL } from '@dfinity/candid';
export const idlFactory: ({ IDL }: { IDL: IDL }) => IDL.ServiceClass;
export const init: ({ IDL }: { IDL: IDL }) => IDL.FuncClass;
