/**
 * Earthflow Écosystème — JavaScript / TypeScript SDK
 * @version 2.0.0
 */

class EarthflowClient {
  constructor({ apiKey, baseUrl = "https://localhost:8443", timeout = 10000 } = {}) {
    if (!apiKey) throw new Error("apiKey is required");
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.timeout = timeout;
  }

  async _request(method, path, body = null) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.apiKey,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      const data = await res.json();
      if (!res.ok) throw Object.assign(new Error(data.message || "Request failed"), { data });
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Submit a request through the Earthflow governance proxy */
  async proxy({ model, messages, metadata = {} }) {
    return this._request("POST", "/v1/proxy", { model, messages, metadata });
  }

  /** List rules for the authenticated tenant */
  async listRules(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._request("GET", `/v1/rules${qs ? "?" + qs : ""}`);
  }

  /** Create a new rule */
  async createRule(rule) {
    return this._request("POST", "/v1/rules", rule);
  }

  /** Update a rule (full replace) */
  async updateRule(ruleId, rule) {
    return this._request("PUT", `/v1/rules/${ruleId}`, rule);
  }

  /** Delete a rule */
  async deleteRule(ruleId) {
    return this._request("DELETE", `/v1/rules/${ruleId}`);
  }

  /** Query audit logs */
  async queryAudit(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._request("GET", `/v1/audit${qs ? "?" + qs : ""}`);
  }

  /** Get audit statistics */
  async auditStats(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._request("GET", `/v1/audit/stats${qs ? "?" + qs : ""}`);
  }

  /** Health check */
  async health() {
    return this._request("GET", "/health");
  }
}

// Node.js / CommonJS export
if (typeof module !== "undefined") module.exports = { EarthflowClient };
// ESM export
export { EarthflowClient };
