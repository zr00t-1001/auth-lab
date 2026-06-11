import { loadVaultSecrets, stopLeaseRenewer } from './vault-secrets';

describe('loadVaultSecrets', () => {
  const ORIG = { ...process.env };
  afterEach(() => {
    stopLeaseRenewer();
    process.env = { ...ORIG };
    jest.restoreAllMocks();
  });

  it('is a no-op when USE_VAULT is not "true"', async () => {
    delete process.env.USE_VAULT;
    const fetchMock = jest.fn();
    (global as any).fetch = fetchMock;
    await loadVaultSecrets();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('logs in via AppRole and injects KV secrets into process.env', async () => {
    process.env.USE_VAULT = 'true';
    process.env.VAULT_ROLE_ID = 'role-123';
    process.env.VAULT_SECRET_ID = 'secret-123';
    delete process.env.USE_VAULT_DB;
    delete process.env.JWT_ACCESS_SECRET;

    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ auth: { client_token: 'tok' } }) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { data: { JWT_ACCESS_SECRET: 'from-vault' } } }),
      });
    (global as any).fetch = fetchMock;

    await loadVaultSecrets();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(process.env.JWT_ACCESS_SECRET).toBe('from-vault');
  });

  it('fetches dynamic DB credentials when USE_VAULT_DB=true', async () => {
    process.env.USE_VAULT = 'true';
    process.env.USE_VAULT_DB = 'true';
    process.env.VAULT_ROLE_ID = 'role-123';
    process.env.VAULT_SECRET_ID = 'secret-123';

    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ auth: { client_token: 'tok' } }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ data: { data: {} } }) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          lease_id: 'database/creds/auth-lab/abc',
          lease_duration: 3600,
          data: { username: 'v-approle-xyz', password: 'dyn-pass' },
        }),
      });
    (global as any).fetch = fetchMock;

    await loadVaultSecrets();

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[2][0]).toContain('/v1/database/creds/auth-lab');
    expect(process.env.DB_USER).toBe('v-approle-xyz');
    expect(process.env.DB_PASS).toBe('dyn-pass');
  });

  it('throws when credentials are missing', async () => {
    process.env.USE_VAULT = 'true';
    delete process.env.VAULT_ROLE_ID;
    delete process.env.VAULT_SECRET_ID;
    delete process.env.VAULT_ROLE_ID_FILE;
    delete process.env.VAULT_SECRET_ID_FILE;
    await expect(loadVaultSecrets()).rejects.toThrow(/credentials are missing/);
  });
});
