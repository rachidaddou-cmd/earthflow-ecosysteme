using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Earthflow.Sdk
{
    /// <summary>Earthflow Écosystème — C# SDK v2.0.0</summary>
    public class EarthflowClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _baseUrl;

        public EarthflowClient(string apiKey, string baseUrl = "https://localhost:8443")
        {
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentException("apiKey required");
            _baseUrl = baseUrl.TrimEnd('/');
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            _http.DefaultRequestHeaders.Add("X-API-Key", apiKey);
        }

        private async Task<T> PostAsync<T>(string path, object body, CancellationToken ct = default)
        {
            var json = JsonSerializer.Serialize(body);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var resp = await _http.PostAsync(_baseUrl + path, content, ct);
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadFromJsonAsync<T>(cancellationToken: ct);
        }

        private async Task<T> GetAsync<T>(string path, CancellationToken ct = default)
        {
            var resp = await _http.GetAsync(_baseUrl + path, ct);
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadFromJsonAsync<T>(cancellationToken: ct);
        }

        /// <summary>Submit a request through the Earthflow governance proxy.</summary>
        public Task<ProxyResponse> ProxyAsync(ProxyRequest request, CancellationToken ct = default)
            => PostAsync<ProxyResponse>("/v1/proxy", request, ct);

        /// <summary>Health check.</summary>
        public Task<HealthResponse> HealthAsync(CancellationToken ct = default)
            => GetAsync<HealthResponse>("/health", ct);

        public void Dispose() => _http.Dispose();
    }

    public record ProxyRequest(string Model, object[] Messages,
                               object Metadata = null);

    public record ProxyResponse(string Status, string RequestId, bool Forwarded,
                                string Reason, int RulesEvaluated, int RulesTriggered,
                                double LatencyMs);

    public record HealthResponse(string Status, string Version);
}
