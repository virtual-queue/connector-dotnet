using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VQueue.Connector;

/// <summary>
/// Verificación del pase de cola (QueuePass) emitido por VQueue.
///
/// Formato, idéntico a VQueue.Lines.QueuePass (Elixir), al core JS y al SDK de PHP:
///
///   base64url(json_payload) "." base64url(hmac_sha256(private_key, base64url(json_payload)))
///
/// Ambas partes SIN padding. El detalle fácil de errar: lo que se firma es el
/// payload YA codificado en base64url, no el JSON crudo.
///
/// El secreto es el private_key de la compañía, así que la verificación es
/// OFFLINE: no hay que llamar a VQueue en cada request.
/// </summary>
public static class QueuePass
{
    public const string CookiePrefix = "vq_pass_";

    /// <summary>Nombre de la cookie del pase para un evento. Es POR evento, no global.</summary>
    public static string CookieName(string eventId) => CookiePrefix + eventId;

    public static PassResult Verify(string? pass, string secret, DateTimeOffset? now = null)
    {
        var nowSeconds = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();

        if (string.IsNullOrEmpty(pass) || string.IsNullOrEmpty(secret))
            return PassResult.Fail("malformed");

        var dot = pass.IndexOf('.');
        if (dot <= 0 || dot == pass.Length - 1)
            return PassResult.Fail("malformed");

        var encoded = pass[..dot];
        var signature = pass[(dot + 1)..];

        // Firma primero: no se decodifica nada que no esté autenticado.
        if (!FixedTimeEquals(Sign(encoded, secret), signature))
            return PassResult.Fail("bad_signature");

        JsonElement payload;
        try
        {
            var json = Base64UrlDecode(encoded);
            payload = JsonDocument.Parse(json).RootElement;
        }
        catch
        {
            return PassResult.Fail("malformed");
        }

        if (payload.ValueKind != JsonValueKind.Object
            || !payload.TryGetProperty("exp", out var expElement)
            || !expElement.TryGetInt64(out var exp))
        {
            return PassResult.Fail("malformed");
        }

        if (exp <= nowSeconds)
            return PassResult.Fail("expired");

        return PassResult.Success(StringOrRaw(payload, "e"), StringOrRaw(payload, "t"), exp);
    }

    // GetString() lanza si el valor no es string: un `e` numérico en un pase
    // bien firmado no debe terminar en excepción (y, vía el catch del guard, en
    // fail-open silencioso).
    private static string? StringOrRaw(JsonElement payload, string name)
    {
        if (!payload.TryGetProperty(name, out var element)) return null;
        return element.ValueKind == JsonValueKind.String ? element.GetString() : element.GetRawText();
    }

    /// <summary>
    /// ¿Hay un pase válido para este evento entre las cookies?
    /// Exige que el <c>e</c> del payload sea el evento consultado: un pase de otro
    /// evento, aunque esté bien firmado, no sirve.
    /// </summary>
    public static PassResult ValidFor(
        IReadOnlyDictionary<string, string> cookies,
        string eventId,
        string secret,
        DateTimeOffset? now = null)
    {
        if (!cookies.TryGetValue(CookieName(eventId), out var raw))
            return PassResult.Fail("absent");

        var result = Verify(raw, secret, now);
        if (!result.Ok)
            return result;

        return result.EventId == eventId ? result : PassResult.Fail("event_mismatch");
    }

    private static string Sign(string encodedPayload, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(encodedPayload));
        return Base64UrlEncode(mac);
    }

    /// <summary>
    /// Comparación en tiempo constante. FixedTimeEquals exige el mismo largo, así
    /// que la diferencia de longitud se responde antes: eso ya se deduce del tamaño
    /// de la cookie, no es información nueva para un atacante.
    /// </summary>
    private static bool FixedTimeEquals(string a, string b)
    {
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);

        return bytesA.Length == bytesB.Length && CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }

    private static string Base64UrlEncode(byte[] raw) =>
        Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Base64UrlDecode(string encoded)
    {
        var padded = encoded.Replace('-', '+').Replace('_', '/');
        // Base64 sin padding: hay que reponerlo para Convert.FromBase64String.
        padded += (encoded.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => "",
            _ => throw new FormatException("base64url inválido"),
        };

        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }
}

public readonly record struct PassResult(bool Ok, string? Reason, string? EventId, string? LineId, long Exp)
{
    public static PassResult Fail(string reason) => new(false, reason, null, null, 0);

    public static PassResult Success(string? eventId, string? lineId, long exp) =>
        new(true, null, eventId, lineId, exp);
}
