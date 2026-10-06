using System.Text.Json;
using System.Text.Json.Serialization;

namespace VQueue.Connector;

public sealed class QueueGuardOptions
{
    /// <summary>Subdominio de la compañía en VQueue.</summary>
    public string Client { get; set; } = "";

    /// <summary>private_key de la compañía. Verifica el pase offline; va por config, no hardcodeada.</summary>
    public string PrivateKey { get; set; } = "";

    public string AdminHost { get; set; } = "clients.virtual-queue.com";
    public TimeSpan SettingsTtl { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Timeout de cada llamada a VQueue (settings y verify). Lo aplica el guard, no depende del HttpClient.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Solo para desarrollo sobre http://localhost. En producción siempre true.</summary>
    public bool SecureCookies { get; set; } = true;

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Client) && !string.IsNullOrWhiteSpace(PrivateKey);
}

/// <summary>Request normalizado: el guard no conoce ASP.NET ni ningún framework. <c>Path</c> va percent-encoded, como lo ve el browser.</summary>
public sealed record QueueRequest(
    string Path,
    IReadOnlyDictionary<string, string> Query,
    IReadOnlyDictionary<string, string> Cookies,
    string Method,
    bool IsWebsocket = false);

public enum DecisionType { Bypass, Allow, Redirect }

public sealed record CookieInstruction(string Name, string Value, int MaxAgeSeconds);

public sealed record Decision(
    DecisionType Type,
    string? Location = null,
    IReadOnlyList<CookieInstruction>? Cookies = null,
    CookieInstruction? Renew = null)
{
    public static readonly Decision Bypass = new(DecisionType.Bypass);
    public static readonly Decision Allow = new(DecisionType.Allow);
}

/// <summary>
/// Protección de cola para apps .NET.
///
/// Mismo contrato que el core JS, el SDK de PHP y el conector de Lambda@Edge;
/// cambia solo el lenguaje. Decide a partir de un request normalizado y devuelve
/// qué hacer, sin tocar la respuesta: de eso se encarga el middleware.
///
/// Todo falla abierto. Sin settings, sin API o con config incompleta, el visitante
/// pasa: un conector que rompe el sitio del cliente es peor que uno que no encola.
/// </summary>
public sealed class QueueGuard
{
    public const string TargetCookiePrefix = "vq_target_";
    private const int TargetTtlSeconds = 3600;

    /// <summary>Mismos límites que el Worker (<c>resolveCookieTtl</c>) y el JS adapter.</summary>
    public const int DefaultCookieLifetime = 600;
    public const int MaxCookieLifetime = 86_400;

    // Tras un fallo se sirve la última config buena y no se reintenta por unos
    // segundos: sin esto, cada request pagaría el timeout entero durante una
    // caída del admin.
    private static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(5);

    private readonly QueueGuardOptions _options;
    private readonly HttpClient _http;
    private readonly ILoggerLike? _logger;
    private readonly Func<DateTimeOffset> _clock;

    // Cache a nivel proceso: ASP.NET es un proceso largo, así que sobrevive entre
    // requests igual que el cache por isolate del Worker.
    private Settings? _cachedSettings;
    private DateTimeOffset _settingsExpire = DateTimeOffset.MinValue;
    private Task<Settings?>? _inflight;
    private readonly object _settingsLock = new();

    public QueueGuard(
        QueueGuardOptions options,
        HttpClient? http = null,
        ILoggerLike? logger = null,
        Func<DateTimeOffset>? clock = null)
    {
        _options = options;
        _http = http ?? new HttpClient();
        _logger = logger;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);

        if (!options.IsConfigured)
        {
            // No se encola a nadie con config incompleta: se avisa y se deja pasar.
            _logger?.Error("[vqueue] conector mal configurado (Client/PrivateKey): dejando pasar todo");
        }
    }

    /// <summary>Si las cookies llevan el flag Secure. Lo consume el middleware.</summary>
    public bool SecureCookies => _options.SecureCookies;

    public static string TargetCookieName(string eventId) => TargetCookiePrefix + eventId;

    /// <summary>
    /// El token de la cola es el id de la línea: un UUID. Mismo filtro que el JS
    /// adapter. Sin él, cada <c>?token=</c> propio del sitio (reset de password,
    /// magic link) costaría un round trip a /queue/verify por página, y cualquiera
    /// podría hacer que el server del cliente golpee la API de VQueue a voluntad.
    /// </summary>
    public static bool IsQueueToken(string? token) =>
        !string.IsNullOrEmpty(token) && Guid.TryParseExact(token, "D", out _);

    public static int ResolveCookieLifetime(long? value)
    {
        if (value is null || value <= 0) return DefaultCookieLifetime;
        return (int)Math.Min(value.Value, MaxCookieLifetime);
    }

    public async Task<Decision> DecideAsync(QueueRequest request, CancellationToken ct = default)
    {
        try
        {
            return await DecideCoreAsync(request, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Red de seguridad final: una excepción nuestra no puede tumbar el
            // sitio del cliente.
            _logger?.Error($"[vqueue] error inesperado, fail-open: {ex}");
            return Decision.Allow;
        }
    }

    private async Task<Decision> DecideCoreAsync(QueueRequest request, CancellationToken ct)
    {
        if (!_options.IsConfigured) return Decision.Allow;

        if (IsBypass(request)) return Decision.Bypass;

        var settings = await GetSettingsAsync().ConfigureAwait(false);
        if (settings is null) return Decision.Allow;

        // 1) Vuelta de la cola con ?vq_token= (o el ?token= legacy)
        if (TryGetToken(request.Query, out var token))
        {
            var exchanged = await ExchangeTokenAsync(token!, settings, ct).ConfigureAwait(false);

            if (exchanged is not null)
            {
                var stored = SafeTarget(
                    request.Cookies.TryGetValue(TargetCookieName(exchanged.EventId), out var t) ? t : null);

                return new Decision(
                    DecisionType.Redirect,
                    stored ?? request.Path + QueryWithoutToken(request.Query),
                    new[]
                    {
                        new CookieInstruction(QueuePass.CookieName(exchanged.EventId), exchanged.Pass, settings.CookieLifetime),
                        new CookieInstruction(TargetCookieName(exchanged.EventId), "", 0),
                    });
            }

            // No era un token de cola: sigue el flujo normal de ACL. Así un
            // ?token= propio del sitio (reset de password, magic link) no se
            // secuestra, y un token vencido no genera el loop cola→sitio→cola.
        }

        // 2) ACLs
        var rule = Acl.FirstMatch(settings.Rules, request.Path);
        if (rule is null || rule.Action != "redirect_to_queue") return Decision.Allow;
        if (string.IsNullOrEmpty(rule.EventId)) return Decision.Allow;

        // 3) ¿Ya tiene pase para este evento?
        var pass = QueuePass.ValidFor(request.Cookies, rule.EventId, _options.PrivateKey, _clock());
        if (pass.Ok)
        {
            // Renovación deslizante: mientras el visitante navegue, el pase se
            // extiende. Sin esto es un presupuesto fijo desde que salió de la fila
            // y una compra lenta vuelve a la cola a mitad de camino.
            return new Decision(
                DecisionType.Allow,
                Renew: new CookieInstruction(
                    QueuePass.CookieName(rule.EventId),
                    request.Cookies[QueuePass.CookieName(rule.EventId)],
                    settings.CookieLifetime));
        }

        _logger?.Log($"[vqueue] sin pase para {rule.EventId} ({pass.Reason}) → cola");

        // 4) A la sala de espera
        return new Decision(
            DecisionType.Redirect,
            $"{settings.QueueUrl.TrimEnd('/')}/queue/{Uri.EscapeDataString(rule.EventId)}",
            new[]
            {
                new CookieInstruction(
                    TargetCookieName(rule.EventId),
                    request.Path + QueryString(request.Query),
                    TargetTtlSeconds),
            });
    }

    /// <summary>
    /// Solo aceptamos un path absoluto propio. Nunca una URL completa: si dejáramos
    /// pasar "https://..." el conector sería un open redirect.
    /// </summary>
    public static string? SafeTarget(string? raw)
    {
        if (string.IsNullOrEmpty(raw) || raw.Length > 2048) return null;
        if (!raw.StartsWith('/')) return null;
        // "//host" es una URL protocol-relative, y los browsers tratan "/\host"
        // exactamente igual.
        if (raw.StartsWith("//", StringComparison.Ordinal) || raw.StartsWith("/\\", StringComparison.Ordinal)) return null;
        if (raw.Contains('\r') || raw.Contains('\n')) return null;

        return raw;
    }

    private bool IsBypass(QueueRequest request)
    {
        if (request.IsWebsocket) return true;

        // Un 302 sobre un POST hace que el browser reintente como GET y pierda el
        // body del checkout.
        if (request.Method is not ("GET" or "HEAD")) return true;

        return request.Path.StartsWith("/api/", StringComparison.Ordinal) || Acl.IsAsset(request.Path);
    }

    private static bool TryGetToken(IReadOnlyDictionary<string, string> query, out string? token)
    {
        if (query.TryGetValue("vq_token", out token) && IsQueueToken(token)) return true;
        if (query.TryGetValue("token", out token) && IsQueueToken(token)) return true;

        token = null;
        return false;
    }

    private async Task<Settings?> GetSettingsAsync()
    {
        Task<Settings?> load;

        lock (_settingsLock)
        {
            // `_settingsExpire` también acota el backoff tras un fallo: con
            // `_cachedSettings` en null, devolver null sin ir a la red es la
            // negative cache.
            if (_clock() < _settingsExpire) return _cachedSettings;

            // Dedup: las requests concurrentes comparten la misma carga en vuelo.
            _inflight ??= LoadSettingsAsync();
            load = _inflight;
        }

        try
        {
            return await load.ConfigureAwait(false);
        }
        finally
        {
            lock (_settingsLock)
            {
                if (ReferenceEquals(_inflight, load)) _inflight = null;
            }
        }
    }

    private async Task<Settings?> LoadSettingsAsync()
    {
        var url = $"https://{_options.AdminHost}/api/v1/adapter/{Uri.EscapeDataString(_options.Client)}/settings";

        // Timeout propio. La carga es compartida por todos los requests que la
        // esperan: si usara el RequestAborted del primero, su desconexión
        // cancelaría la de todos los demás.
        using var cts = new CancellationTokenSource(_options.Timeout);

        Settings? fresh = null;
        try
        {
            var body = await _http.GetFromJsonSafeAsync<SettingsEnvelope>(url, cts.Token).ConfigureAwait(false);
            fresh = Normalize(body?.Data);
            if (fresh is null) _logger?.Warn("[vqueue] settings con forma inesperada");
        }
        catch (Exception ex)
        {
            _logger?.Warn($"[vqueue] settings no disponibles: {ex.Message}");
        }

        lock (_settingsLock)
        {
            if (fresh is not null)
            {
                _cachedSettings = fresh;
                _settingsExpire = _clock().Add(_options.SettingsTtl);
            }
            else
            {
                // Ante un fallo se sirve la última config buena (si la hay):
                // mejor eso que dejar el origen sin protección por un hipo de red.
                _settingsExpire = _clock().Add(RetryAfter);
            }

            return _cachedSettings;
        }
    }

    private static Settings? Normalize(SettingsData? data)
    {
        if (data?.Acls is null) return null;

        // Sin queue_url no hay a dónde mandar a nadie: mejor "sin settings" (y
        // fail-open explícito) que un redirect a "/queue/..." del propio sitio.
        var queueUrl = data.QueueUrl;
        if (string.IsNullOrEmpty(queueUrl)
            || !(queueUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                 || queueUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        return new Settings(queueUrl, ResolveCookieLifetime(data.CookieLifetime), Acl.Sort(data.Acls));
    }

    private async Task<ExchangedToken?> ExchangeTokenAsync(string token, Settings settings, CancellationToken ct)
    {
        var url = $"{settings.QueueUrl.TrimEnd('/')}/api/v1/queue/verify?token={Uri.EscapeDataString(token)}";

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_options.Timeout);

        try
        {
            var body = await _http.GetFromJsonSafeAsync<VerifyEnvelope>(url, cts.Token).ConfigureAwait(false);

            if (body?.Success != true || string.IsNullOrEmpty(body.Data?.EventId)) return null;

            // Sin pase no hay nada que verificar offline. El JS adapter cae al
            // token crudo porque no puede verificar nada de todos modos; acá ese
            // fallback solo produciría una cookie que nunca valida y mandaría al
            // visitante a la cola en la página siguiente. Se trata como canje
            // fallido y se avisa fuerte.
            if (string.IsNullOrEmpty(body.Data.Pass))
            {
                _logger?.Error($"[vqueue] VQueue no devolvió el pase para {body.Data.EventId}: fallo al firmar del lado de la cola");
                return null;
            }

            return new ExchangedToken(body.Data.EventId, body.Data.Pass);
        }
        catch (Exception ex)
        {
            _logger?.Warn($"[vqueue] verify falló: {ex.Message}");
            return null;
        }
    }

    private static string QueryString(IReadOnlyDictionary<string, string> query) =>
        query.Count == 0
            ? ""
            : "?" + string.Join("&", query.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

    private static string QueryWithoutToken(IReadOnlyDictionary<string, string> query) =>
        QueryString(query
            .Where(kv => kv.Key is not ("vq_token" or "token"))
            .ToDictionary(kv => kv.Key, kv => kv.Value));

    internal sealed record Settings(string QueueUrl, int CookieLifetime, List<AclRule> Rules);

    private sealed record ExchangedToken(string EventId, string Pass);

    private sealed class SettingsEnvelope
    {
        [JsonPropertyName("data")] public SettingsData? Data { get; set; }
    }

    private sealed class SettingsData
    {
        [JsonPropertyName("queue_url")] public string? QueueUrl { get; set; }

        // Nullable y tolerante a "600": un valor raro del admin no puede tirar
        // abajo toda la deserialización (y con ella la protección).
        [JsonPropertyName("cookie_lifetime")]
        [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
        public long? CookieLifetime { get; set; }

        [JsonPropertyName("acls")] public List<AclRule>? Acls { get; set; }
    }

    private sealed class VerifyEnvelope
    {
        [JsonPropertyName("success")] public bool Success { get; set; }
        [JsonPropertyName("data")] public VerifyData? Data { get; set; }
    }

    private sealed class VerifyData
    {
        [JsonPropertyName("event_id")] public string? EventId { get; set; }
        [JsonPropertyName("pass")] public string? Pass { get; set; }
    }
}

/// <summary>Logger mínimo para no imponerle Microsoft.Extensions.Logging a quien no lo use.</summary>
public interface ILoggerLike
{
    void Log(string message);
    void Warn(string message);
    void Error(string message);
}

internal static class HttpClientJsonExtensions
{
    public static async Task<T?> GetFromJsonSafeAsync<T>(this HttpClient http, string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");

        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct)
            .ConfigureAwait(false);

        // Un 3xx en un endpoint JSON es un problema de routing, no algo a seguir:
        // siguiéndolo, un loop de CDN se come todo el canje.
        if ((int)response.StatusCode is >= 300 and < 400)
            throw new HttpRequestException($"redirect inesperado a {response.Headers.Location}");

        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"status {(int)response.StatusCode}");

        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);

        return await JsonSerializer.DeserializeAsync<T>(stream, cancellationToken: ct).ConfigureAwait(false);
    }
}
