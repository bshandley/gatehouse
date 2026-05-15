export interface GatehouseConfig {
  port: number;
  dataDir: string;
  configDir: string;
  masterKey: Buffer;
  jwtSecret: string;
  publicUrl?: string;
  internalUrl?: string;
}

export function loadConfig(): GatehouseConfig {
  const masterKeyHex = process.env.GATEHOUSE_MASTER_KEY;
  if (!masterKeyHex || masterKeyHex.length < 64) {
    throw new Error(
      "GATEHOUSE_MASTER_KEY must be set (64-char hex string, e.g. openssl rand -hex 32)"
    );
  }

  const masterKey = Buffer.from(masterKeyHex, "hex");

  const { deriveKey } = require("./secrets/engine");
  const jwtSecret =
    process.env.GATEHOUSE_JWT_SECRET ||
    Buffer.from(deriveKey(masterKey, "gatehouse-jwt")).toString("hex");

  return {
    port: parseInt(process.env.GATEHOUSE_PORT || "3100", 10),
    dataDir: process.env.GATEHOUSE_DATA_DIR || "/data",
    configDir: process.env.GATEHOUSE_CONFIG_DIR || "/config",
    masterKey,
    jwtSecret,
    publicUrl: process.env.GATEHOUSE_PUBLIC_URL?.replace(/\/$/, "") || undefined,
    internalUrl: process.env.GATEHOUSE_INTERNAL_URL?.replace(/\/$/, "") || undefined,
  };
}
