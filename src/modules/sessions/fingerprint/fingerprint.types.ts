export type SessionFingerprint = {
  hash: string;

  raw: {
    ip: string;
    userAgent: string;
    os?: string;
    browser?: string;
    deviceType?: string;
  };
};