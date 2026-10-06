using System.Net;
using Microsoft.AspNetCore.Http;
using VQueue.Connector;
using Xunit;

namespace VQueue.Connector.Tests;

public class QueueMiddlewareTests
{
    private const string Secret = "test-private-key-abc123";
    private const string Pass =
        "eyJlIjoiZXYtNDIiLCJleHAiOjE3MDAwMDM2MDAsImlhdCI6MTcwMDAwMDAwMCwidCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSJ9"
        + ".AjaVlbsXru7V8GOJuhEV2doxd3W1-dQlEVTi5BEnNco";
    private const string Token = "11111111-1111-1111-1111-111111111111";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_100);

    private static QueueGuard Guard(bool verifyOk = false)
    {
        var http = new StubHandler
        {
            Respond = req =>
            {
                if (req.RequestUri!.AbsolutePath.Contains("/adapter/"))
                {
                    return StubHandler.Json(new
                    {
                        success = true,
                        data = new
                        {
                            queue_url = "https://orome.virtual-queue.com",
                            cookie_lifetime = 600,
                            acls = new[] { new { action = "redirect_to_queue", pattern = "/shop", pattern_type = "prefix", event_id = "ev-42", priority = 0, enabled = true } },
                        },
                    });
                }

                return verifyOk
                    ? StubHandler.Json(new { success = true, data = new { event_id = "ev-42", pass = Pass } })
                    : StubHandler.Json(new { success = false }, HttpStatusCode.BadRequest);
            },
        };

        return new QueueGuard(
            new QueueGuardOptions { Client = "orome", PrivateKey = Secret, AdminHost = "admin.test" },
            new HttpClient(http),
            clock: () => Now);
    }

    private static DefaultHttpContext Context(string path, string query = "", string? cookie = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = path;
        ctx.Request.QueryString = new QueryString(query);
        if (cookie is not null) ctx.Request.Headers.Cookie = cookie;
        return ctx;
    }

    [Fact]
    public async Task Redirige_a_la_cola_con_302_y_cookie_de_destino_sin_seguir_la_cadena()
    {
        var called = false;
        var middleware = new QueueMiddleware(_ => { called = true; return Task.CompletedTask; }, Guard());
        var ctx = Context("/shop/entradas", "?fila=3");

        await middleware.InvokeAsync(ctx);

        Assert.False(called);
        Assert.Equal(302, ctx.Response.StatusCode);
        Assert.Equal("https://orome.virtual-queue.com/queue/ev-42", ctx.Response.Headers.Location.ToString());
        Assert.Equal("no-store", ctx.Response.Headers.CacheControl.ToString());
        Assert.Contains(ctx.Response.Headers.SetCookie.ToArray(), c => c!.StartsWith("vq_target_ev-42=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Deja_pasar_con_pase_y_renueva_la_cookie()
    {
        var called = false;
        var middleware = new QueueMiddleware(_ => { called = true; return Task.CompletedTask; }, Guard());
        var ctx = Context("/shop/entradas", cookie: $"vq_pass_ev-42={Pass}");

        await middleware.InvokeAsync(ctx);

        Assert.True(called);
        var renewed = Assert.Single(ctx.Response.Headers.SetCookie.ToArray());
        Assert.StartsWith($"vq_pass_ev-42={Pass};", renewed);
        Assert.Contains("httponly", renewed!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", renewed!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Un_path_con_caracteres_no_ascii_vuelve_escapado_en_el_location()
    {
        // Kestrel entrega Path decodificado; un Location con "ñ" o espacio sería
        // un header inválido (excepción, 500 al visitante).
        var middleware = new QueueMiddleware(_ => Task.CompletedTask, Guard(verifyOk: true));
        var ctx = Context("/shop/entradas ñ", $"?vq_token={Token}");

        await middleware.InvokeAsync(ctx);

        Assert.Equal(302, ctx.Response.StatusCode);
        Assert.Equal("/shop/entradas%20%C3%B1", ctx.Response.Headers.Location.ToString());
    }
}
