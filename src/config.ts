export interface GatehouseConfig {
  port: number;
  dataDir: string;
  configDir: string;
  masterKey: Buffer;
  jwtSecret: string;
  oauth?: {
    issuer: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  };
}

export function loadConfig(): GatehouseConfig {
  const masterKeyHex = process.env.GATEHOUSE_MASTER_KEY;
  if (!masterKeyHex || masterKeyHex.length < 64) {
    throw new Error(
      "GATEHOUSE_MASTER_KEY must be set (64-char hex string, e.g. openssl rand -hex 32)"
    );
  }

  const masterKey = Buffer.from(masterKeyHex, "hex");

  // Derive JWT secret via HKDF with domain separation (not raw master key)
  const { deriveKey } = require("./secrets/engine");
  const jwtSecret =
    process.env.GATEHOUSE_JWT_SECRET ||
    Buffer.from(deriveKey(masterKey, "gatehouse-jwt")).toString("hex");

  const config: GatehouseConfig = {
    port: parseInt(process.env.GATEHOUSE_PORT || "3100", 10),
    dataDir: process.env.GATEHOUSE_DATA_DIR || "/data",
    configDir: process.env.GATEHOUSE_CONFIG_DIR || "/config",
    masterKey,
    jwtSecret,
  };

  // Optional OAuth (PocketID)
  if (process.env.GATEHOUSE_OAUTH_ISSUER) {
    config.oauth = {
      issuer: process.env.GATEHOUSE_OAUTH_ISSUER,
      clientId: process.env.GATEHOUSE_OAUTH_CLIENT_ID || "",
      clientSecret: process.env.GATEHOUSE_OAUTH_CLIENT_SECRET || "",
      redirectUri: process.env.GATEHOUSE_OAUTH_REDIRECT_URI || "",
    };
  }

  return config;
}
