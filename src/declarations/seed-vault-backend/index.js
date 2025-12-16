import { HttpAgent, Actor } from '@dfinity/agent';

const canisterId = process.env.CANISTER_ID_SEED_VAULT_BACKEND || '';

const idlFactory = () => {
  throw new Error('Run `dfx generate seed-vault-backend` to obtain candid definitions.');
};

export function createActor(id = canisterId, options = {}) {
  if (!id) {
    throw new Error('Missing canister ID for seed-vault-backend.');
  }
  const agent = options.agentOptions
    ? new HttpAgent(options.agentOptions)
    : new HttpAgent({ host: options.host });
  return Actor.createActor(idlFactory, { agent, canisterId: id });
}

export const seed_vault_backend = new Proxy(
  {},
  {
    get() {
      throw new Error('seed-vault-backend declarations are unavailable; regenerate with dfx.');
    },
  },
);
export { canisterId };
