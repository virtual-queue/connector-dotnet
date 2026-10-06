using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace VQueue.Connector;

/// <summary>
/// Middleware de ASP.NET Core. Traduce el <see cref="HttpContext"/> al request
/// normalizado del guard y aplica la decisión sobre la respuesta.
///
/// A diferencia de Lambda@Edge, acá la renovación deslizante se resuelve en una
/// sola pasada: el middleware puede tocar la respuesta antes de que salga, así
/// que no hace falta una segunda función.
/// </summary>
public sealed class QueueMiddleware
{
    private readonly RequestDelegate _next;
    private readonly QueueGuard _guard;

    public QueueMiddleware(RequestDelegate next, QueueGuard guard)
    {
        _next = next;
        _guard = guard;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var decision = await _guard.DecideAsync(ToRequest(context.Request), context.RequestAborted)
            .ConfigureAwait(false);

        if (decision.Type == DecisionType.Redirect)
        {
            foreach (var cookie in decision.Cookies ?? Array.Empty<CookieInstruction>())
            {
                Append(context.Response, cookie);
            }

            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = decision.Location;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        if (decision.Renew is not null)
        {
            Append(context.Response, decision.Renew);
        }

        await _next(context).ConfigureAwait(false);
    }

    private void Append(HttpResponse response, CookieInstruction cookie)
    {
        response.Cookies.Append(cookie.Name, cookie.Value, new CookieOptions
        {
            Path = "/",
            MaxAge = TimeSpan.FromSeconds(cookie.MaxAgeSeconds),
            HttpOnly = true,
            Secure = _guard.SecureCookies,
            SameSite = SameSiteMode.Lax,
        });
    }

    private static QueueRequest ToRequest(HttpRequest request)
    {
        var query = request.Query.ToDictionary(
            kv => kv.Key,
            kv => kv.Value.ToString(),
            StringComparer.Ordinal);

        var cookies = request.Cookies.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);

        var upgrade = request.Headers.Upgrade.ToString();

        // `Path.Value` viene DECODIFICADO (Kestrel desescapa el %XX). Para
        // matchear igual que los Workers y para reusarlo como Location sin que
        // un espacio o una ñ terminen en un header inválido, va re-escapado.
        var path = request.Path.HasValue ? request.Path.ToUriComponent() : "/";

        return new QueueRequest(
            path,
            query,
            cookies,
            request.Method,
            upgrade.Equals("websocket", StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>Azúcar para registrarlo: <c>app.UseVQueue();</c></summary>
public static class QueueMiddlewareExtensions
{
    public static IApplicationBuilder UseVQueue(this IApplicationBuilder app) =>
        app.UseMiddleware<QueueMiddleware>();
}
