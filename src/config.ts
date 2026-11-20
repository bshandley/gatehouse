import { resolveMasterKey, type MasterKeySource } from "./backup/keyfile";

export interface GatehouseConfig {
  port: number;
  dataDir: string;
  configDir: string;
  masterKey: Buffer;
  masterKeySource: MasterKeySource;
  jwtSecret: string;
  publicUrl?: string;
  internalUrl?: string;
}

/** allowGenerate false: never create a key (the stdio MCP server must not create a vault). */
export function loadConfig(opts: { allowGenerate?: boolean } = {}): GatehouseConfig {
  const dataDir = process.env.GATEHOUSE_DATA_DIR || "/data";
  const { key: masterKey, source: masterKeySource } = resolveMasterKey({
    envKey: process.env.GATEHOUSE_MASTER_KEY,
    dataDir,
    allowGenerate: opts.allowGenerate ?? true,
  });

  const { deriveKey } = require("./secrets/engine");
  const jwtSecret =
    process.env.GATEHOUSE_JWT_SECRET ||
    Buffer.from(deriveKey(masterKey, "gatehouse-jwt")).toString("hex");

  return {
    port: parseInt(process.env.GATEHOUSE_PORT || "3100", 10),
    dataDir,
    configDir: process.env.GATEHOUSE_CONFIG_DIR || "/config",
    masterKey,
    masterKeySource,
    jwtSecret,
    publicUrl: process.env.GATEHOUSE_PUBLIC_URL?.replace(/\/$/, "") || undefined,
    internalUrl: process.env.GATEHOUSE_INTERNAL_URL?.replace(/\/$/, "") || undefined,
  };
}
