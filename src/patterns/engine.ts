import { Database } from "bun:sqlite";
import type {
  BodySchema,
  PatternOutcome,
  ProxyPattern,
  PatternWithConfidence,
  PatternSuggestion,
  RecordInput,
} from "./types";

const MAX_OUTCOMES = 20;

interface RawPattern {
  id: string;
  secret_path: string;
  method: string;
  url_template: string;
  host: string;
  request_headers: string;
  request_body_schema: string | null;
  response_status: number;
  response_body_schema: string | null;
  recent_outcomes: string;
  agents: string;
  total_successes: number;
  total_failures: number;
  pinned: number;
  created_at: string;
  updated_at: string;
}

export class PatternEngine {
  private db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  normalizeUrl(raw: string): string {
    // Parse out fragment manually before URL parsing (URL drops fragments inconsistently)
    const withoutFragment = raw.split("#")[0];

    let parsed: URL;
    try {
      parsed = new URL(withoutFragment);
    } catch {
      return raw;
    }

    // Normalize path segments
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const NUM_RE = /^\d+$/;
    // ISO date: YYYY-MM-DD (but not UUIDs which also have dashes)
    const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

    const segments = parsed.pathname.split("/").map((seg) => {
      if (UUID_RE.test(seg)) return ":id";
      if (DATE_RE.test(seg)) return ":date";
      if (NUM_RE.test(seg)) return ":num";
      return seg;
    });

    const normalizedPath = segments.join("/");

    // Normalize query: keep sorted keys, strip values
    let queryStr = "";
    if (parsed.search) {
      const keys = Array.from(parsed.searchParams.keys()).sort();
      queryStr = "?" + keys.map((k) => `${k}=`).join("&");
    }

    // Reconstruct: scheme + host (includes port) + path + query
    const base = `${parsed.protocol}//${parsed.host}`;
    return base + normalizedPath + queryStr;
  }

  extractSchema(data: any): BodySchema | null {
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      return null;
    }

    const keys = Object.keys(data);
    if (keys.length === 0) return null;

    const schema: BodySchema = {};
    for (const key of keys) {
      const val = data[key];
      if (val === null) {
        schema[key] = "null";
      } else if (Array.isArray(val)) {
        if (val.length === 0) {
          schema[key] = "array<unknown>";
        } else {
          const elementTypes = new Set(val.map((item) => typeof item));
          if (elementTypes.size === 1) {
            schema[key] = `array<${[...elementTypes][0]}>`;
          } else {
            schema[key] = "array<mixed>";
          }
        }
      } else if (typeof val === "object") {
        schema[key] = "object";
      } else {
        schema[key] = typeof val;
      }
    }

    return schema;
  }

  private computeConfidence(outcomes: PatternOutcome[]): number {
    if (outcomes.length === 0) return 0;
    const successes = outcomes.filter((o) => o.success).length;
    return successes / outcomes.length;
  }

  private rawToPattern(raw: RawPattern): PatternWithConfidence {
    const recent_outcomes: PatternOutcome[] = JSON.parse(raw.recent_outcomes || "[]");
    const agents: string[] = JSON.parse(raw.agents || "[]");
    const confidence = this.computeConfidence(recent_outcomes);
    const verified_by = new Set(agents).size;

    return {
      id: raw.id,
      secret_path: raw.secret_path,
      method: raw.method,
      url_template: raw.url_template,
      host: raw.host,
      request_headers: JSON.parse(raw.request_headers || "[]"),
      request_body_schema: raw.request_body_schema ? JSON.parse(raw.request_body_schema) : null,
      response_status: raw.response_status,
      response_body_schema: raw.response_body_schema ? JSON.parse(raw.response_body_schema) : null,
      recent_outcomes,
      agents,
      total_successes: raw.total_successes,
      total_failures: raw.total_failures,
      pinned: raw.pinned === 1,
      created_at: raw.created_at,
      updated_at: raw.updated_at,
      confidence,
      verified_by,
    };
  }

  record(input: RecordInput): void {
    const { secret_paths, method, url, request_headers, request_body, response_status, response_body, identity } = input;
    const isSuccess = response_status >= 200 && response_status < 300;
    const urlTemplate = this.normalizeUrl(url);

    let host: string;
    try {
      host = new URL(url).hostname;
    } catch {
      host = "";
    }

    const reqSchema = this.extractSchema(request_body);
    const resSchema = this.extractSchema(response_body);
    const now = new Date().toISOString();

    for (const secretPath of secret_paths) {
      const existing = this.db
        .query<RawPattern, [string, string, string]>(
          "SELECT * FROM proxy_patterns WHERE secret_path = ? AND method = ? AND url_template = ?"
        )
        .get(secretPath, method, urlTemplate);

      if (existing) {
        // Update existing pattern
        const outcomes: PatternOutcome[] = JSON.parse(existing.recent_outcomes || "[]");
        outcomes.push({ agent: identity, success: isSuccess, timestamp: now });
        while (outcomes.length > MAX_OUTCOMES) outcomes.shift();

        const agents: string[] = JSON.parse(existing.agents || "[]");
        if (!agents.includes(identity)) agents.push(identity);

        const totalSuccesses = existing.total_successes + (isSuccess ? 1 : 0);
        const totalFailures = existing.total_failures + (isSuccess ? 0 : 1);

        // Merge schemas on success
        let mergedReqSchema: BodySchema | null = existing.request_body_schema
          ? JSON.parse(existing.request_body_schema)
          : null;
        let mergedResSchema: BodySchema | null = existing.response_body_schema
          ? JSON.parse(existing.response_body_schema)
          : null;

        if (isSuccess) {
          if (reqSchema) {
            mergedReqSchema = { ...(mergedReqSchema ?? {}), ...reqSchema };
          }
          if (resSchema) {
            mergedResSchema = { ...(mergedResSchema ?? {}), ...resSchema };
          }
        }

        const updatedStatus = isSuccess ? response_status : existing.response_status;

        this.db
          .query(
            `UPDATE proxy_patterns SET
              recent_outcomes = ?,
              agents = ?,
              total_successes = ?,
              total_failures = ?,
              request_body_schema = ?,
              response_body_schema = ?,
              response_status = ?,
              updated_at = ?
            WHERE id = ?`
          )
          .run(
            JSON.stringify(outcomes),
            JSON.stringify(agents),
            totalSuccesses,
            totalFailures,
            mergedReqSchema ? JSON.stringify(mergedReqSchema) : null,
            mergedResSchema ? JSON.stringify(mergedResSchema) : null,
            updatedStatus,
            now,
            existing.id
          );
      } else {
        // New pattern - only create from successes
        if (!isSuccess) continue;

        const id = crypto.randomUUID();
        const outcome: PatternOutcome = { agent: identity, success: true, timestamp: now };

        this.db
          .query(
            `INSERT INTO proxy_patterns
              (id, secret_path, method, url_template, host, request_headers,
               request_body_schema, response_status, response_body_schema,
               recent_outcomes, agents, total_successes, total_failures, pinned,
               created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            id,
            secretPath,
            method,
            urlTemplate,
            host,
            JSON.stringify(request_headers),
            reqSchema ? JSON.stringify(reqSchema) : null,
            response_status,
            resSchema ? JSON.stringify(resSchema) : null,
            JSON.stringify([outcome]),
            JSON.stringify([identity]),
            1,
            0,
            0,
            now,
            now
          );
      }
    }
  }

  query(secretPath: string): PatternWithConfidence[] {
    const rows = this.db
      .query<RawPattern, [string]>(
        "SELECT * FROM proxy_patterns WHERE secret_path = ?"
      )
      .all(secretPath);

    return rows
      .map((r) => this.rawToPattern(r))
      .sort((a, b) => b.confidence - a.confidence);
  }

  listAll(): PatternWithConfidence[] {
    const rows = this.db
      .query<RawPattern, []>("SELECT * FROM proxy_patterns")
      .all();

    return rows
      .map((r) => this.rawToPattern(r))
      .sort((a, b) => b.confidence - a.confidence);
  }

  suggest(secretPath: string): PatternSuggestion[] {
    const patterns = this.query(secretPath);
    const filtered = patterns.filter((p) => p.pinned || p.confidence > 0.5);

    return filtered.slice(0, 5).map((p) => ({
      method: p.method,
      url_template: p.url_template,
      request_headers: p.request_headers,
      request_body_schema: p.request_body_schema,
      confidence: p.confidence,
      verified_by: p.verified_by,
    }));
  }

  delete(id: string): boolean {
    const result = this.db
      .query("DELETE FROM proxy_patterns WHERE id = ?")
      .run(id);
    return (result.changes ?? 0) > 0;
  }

  togglePin(id: string): boolean {
    const result = this.db
      .query("UPDATE proxy_patterns SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE id = ?")
      .run(id);
    return (result.changes ?? 0) > 0;
  }
}
