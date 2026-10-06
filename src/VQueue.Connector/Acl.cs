using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace VQueue.Connector;

/// <summary>Una regla de ACL, tal como la sirve el endpoint público del admin.</summary>
public sealed class AclRule
{
    [JsonPropertyName("action")] public string? Action { get; set; }
    [JsonPropertyName("pattern")] public string? Pattern { get; set; }
    [JsonPropertyName("pattern_type")] public string? PatternType { get; set; }
    [JsonPropertyName("event_id")] public string? EventId { get; set; }
    [JsonPropertyName("priority")]
    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
    public int? Priority { get; set; }
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
}

/// <summary>
/// Matcheo de ACLs. Misma semántica que el core JS, el SDK de PHP, los Workers y
/// el JS adapter: reglas habilitadas, prioridad ascendente, gana el primer match.
/// </summary>
public static class Acl
{
    /// <summary>
    /// `.json` queda FUERA a propósito: lo usan endpoints dinámicos
    /// (/products.json, /cart.json) que son justamente los que hay que proteger.
    /// Debe mantenerse en sintonía con las demás integraciones.
    /// </summary>
    private static readonly Regex AssetRegex = new(
        @"\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|map)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Dictionary<string, Regex> GlobCache = new();
    private static readonly object GlobLock = new();
    private const int MaxGlobCache = 1000;

    public static bool IsAsset(string path) => AssetRegex.IsMatch(path);

    public static bool Matches(AclRule rule, string path)
    {
        // Un pattern vacío no matchea nada. StartsWith("") es true para cualquier
        // path, y una regla mal cargada no puede encolar el sitio entero por
        // accidente: misma política que el core JS y PHP.
        if (string.IsNullOrEmpty(rule.Pattern)) return false;

        return rule.PatternType switch
        {
            "prefix" => path.StartsWith(rule.Pattern, StringComparison.Ordinal),
            "exact" => string.Equals(rule.Pattern, path, StringComparison.Ordinal),
            "contains" => path.Contains(rule.Pattern, StringComparison.Ordinal),
            "glob" => GlobRegex(rule.Pattern).IsMatch(path),
            _ => false,
        };
    }

    /// <summary>
    /// Ordena una vez por refresco de settings, no por request. Las reglas sin
    /// prioridad van al final con un peso finito: dejarlas indefinidas haría que
    /// cuál regla gana dependa del algoritmo de ordenamiento.
    /// </summary>
    public static List<AclRule> Sort(IEnumerable<AclRule>? rules) =>
        (rules ?? Enumerable.Empty<AclRule>())
            .Where(r => r is { Enabled: true })
            .OrderBy(r => r.Priority ?? int.MaxValue)
            .ToList();

    public static AclRule? FirstMatch(IReadOnlyList<AclRule> sortedRules, string path)
    {
        foreach (var rule in sortedRules)
        {
            if (Matches(rule, path)) return rule;
        }

        return null;
    }

    private static Regex GlobRegex(string pattern)
    {
        lock (GlobLock)
        {
            if (GlobCache.TryGetValue(pattern, out var cached)) return cached;

            // Se escapa todo y después se reabre solo `*`: un `.` o un `(` en el
            // patrón no deben comportarse como metacaracteres de regex.
            var regex = new Regex("^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$", RegexOptions.Compiled);

            if (GlobCache.Count >= MaxGlobCache) GlobCache.Clear();
            GlobCache[pattern] = regex;

            return regex;
        }
    }
}
