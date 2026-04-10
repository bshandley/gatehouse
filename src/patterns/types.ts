export interface BodySchema {
  [key: string]: string;
}

export interface PatternOutcome {
  agent: string;
  success: boolean;
  timestamp: string;
}

export interface ProxyPattern {
  id: string;
  secret_path: string;
  method: string;
  url_template: string;
  host: string;
  request_headers: string[];
  request_body_schema: BodySchema | null;
  response_status: number;
  response_body_schema: BodySchema | null;
  recent_outcomes: PatternOutcome[];
  agents: string[];
  total_successes: number;
  total_failures: number;
  pinned: boolean;
  created_at: string;
  updated_at: string;
}

export interface PatternWithConfidence extends ProxyPattern {
  confidence: number;
  verified_by: number;
}

export interface RecordInput {
  secret_paths: string[];
  method: string;
  url: string;
  request_headers: string[];
  request_body: any;
  response_status: number;
  response_body: any;
  identity: string;
}

export interface PatternSuggestion {
  method: string;
  url_template: string;
  request_headers: string[];
  request_body_schema: BodySchema | null;
  confidence: number;
  verified_by: number;
}
