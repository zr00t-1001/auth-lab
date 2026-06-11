import { loadVaultSecrets } from './vault-secrets';

describe('loadVaultSecrets', () => {
  const ORIG = { ...process.env };
  afterEach(() => {
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

  it('logs in via AppRole and injects the secret into process.env', async () => {
    process.env.USE_VAULT = 'true';
    process.env.VAULT_ADDR = 'http://vault:8200';
    process.env.VAULT_ROLE_ID = 'role-123';
    process.env.VAULT_SECRET_ID = 'secret-123';
    delete process.env.JWT_ACCESS_SECRET;

    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ auth: { client_token: 'tok-abc' } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { data: { JWT_ACCESS_SECRET: 'from-vault', DB_PASS: 'pw' } } }),
      });
    (global as any).fetch = fetchMock;

    await loadVaultSecrets();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toContain('/v1/auth/approle/login');
    expect(fetchMock.mock.calls[1][1].headers['X-Vault-Token']).toBe('tok-abc');
    expect(process.env.JWT_ACCESS_SECRET).toBe('from-vault');
    expect(process.env.DB_PASS).toBe('pw');
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
