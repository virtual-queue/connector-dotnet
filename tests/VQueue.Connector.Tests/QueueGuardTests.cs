using System.Net;
using System.Text;
using System.Text.Json;
using VQueue.Connector;
using Xunit;

namespace VQueue.Connector.Tests;

/// <summary>Doble de HttpClient: responde según la URL y cuenta llamadas.</summary>
internal sealed class StubHandler : HttpMessageHandler
{
    public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; } = _ => new(HttpStatusCode.NotFound);
    public int Calls { get; private set; }
    public int VerifyCalls { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Calls++;
        if (request.RequestUri!.AbsolutePath.Contains("/queue/verify")) VerifyCalls++;
        return Task.FromResult(Respond(request));
    }

    public static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
}

public class QueueGuardTests
{
    private const string Secret = "test-private-key-abc123";
    private const string Pass =
        "eyJlIjoiZXYtNDIiLCJleHAiOjE3MDAwMDM2MDAsImlhdCI6MTcwMDAwMDAwMCwidCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSJ9"
        + ".AjaVlbsXru7V8GOJuhEV2doxd3W1-dQlEVTi5BEnNco";
    private const string Token = "11111111-1111-1111-1111-111111111111";

    // Dentro de la validez del vector de Elixir (exp = 1700003600).
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_100);

    private static object SettingsBody(string? queueUrl = "https://orome.virtual-queue.com", long? cookieLifetime = 600) => new
    {
        success = true,
        data = new
        {
            client = "orome",
            queue_url = queueUrl,
            cookie_lifetime = cookieLifetime,
            acls = new[]
            {
                new { action = "redirect_to_queue", pattern = "/shop", pattern_type = "prefix", event_id = "ev-42", priority = 0, enabled = true },
            },
        },
    };

    private static (QueueGuard guard, StubHandler http) Guard(
        Func<HttpRequestMessage, HttpResponseMessage>? respond = null,
        Func<DateTimeOffset>? clock = null,
        TimeSpan? settingsTtl = null)
    {
        var http = new StubHandler();
        http.Respond = respond ?? (req => req.RequestUri!.AbsolutePath.Contains("/adapter/")
            ? StubHandler.Json(SettingsBody())
            : StubHandler.Json(new { success = false }, HttpStatusCode.BadRequest));

        var options = new QueueGuardOptions
        {
            Client = "orome",
            PrivateKey = Secret,
            AdminHost = "admin.test",
            SettingsTtl = settingsTtl ?? TimeSpan.FromSeconds(30),
        };

        return (new QueueGuard(options, new HttpClient(http), clock: clock ?? (() => Now)), http);
    }

    private static QueueRequest Request(
        string path = "/shop/entradas",
        IDictionary<string, string>? query = null,
        IDictionary<string, string>? cookies = null,
        string method = "GET") =>
        new(path,
            new Dictionary<string, string>(query ?? new Dictionary<string, string>()),
            new Dictionary<string, string>(cookies ?? new Dictionary<string, string>()),
            method);

    [Fact]
    public async Task Manda_a_la_cola_al_visitante_sin_pase()
    {
        var (guard, _) = Guard();

        var d = await guard.DecideAsync(Request(query: new Dictionary<string, string> { ["fila"] = "3" }));

        Assert.Equal(DecisionType.Redirect, d.Type);
        Assert.Equal("https://orome.virtual-queue.com/queue/ev-42", d.Location);
        Assert.Equal("/shop/entradas?fila=3", d.Cookies![0].Value);
    }

    [Fact]
    public async Task Deja_pasar_al_que_tiene_pase_valido_y_lo_renueva()
    {
        var (guard, _) = Guard();

        var d = await guard.DecideAsync(Request(cookies: new Dictionary<string, string> { [QueuePass.CookieName("ev-42")] = Pass }));

        Assert.Equal(DecisionType.Allow, d.Type);
        Assert.Equal(Pass, d.Renew!.Value);
        Assert.Equal(600, d.Renew.MaxAgeSeconds);
    }

    [Fact]
    public async Task Con_pase_vencido_vuelve_a_la_cola()
    {
        var (guard, _) = Guard(clock: () => DateTimeOffset.FromUnixTimeSeconds(1_700_003_601));

        var d = await guard.DecideAsync(Request(cookies: new Dictionary<string, string> { [QueuePass.CookieName("ev-42")] = Pass }));

        Assert.Equal(DecisionType.Redirect, d.Type);
    }

    [Fact]
    public async Task Saltea_assets_y_post_sin_tocar_la_red()
    {
        var (guard, http) = Guard();

        Assert.Equal(DecisionType.Bypass, (await guard.DecideAsync(Request(path: "/shop/app.css"))).Type);
        Assert.Equal(DecisionType.Bypass, (await guard.DecideAsync(Request(method: "POST"))).Type);
        Assert.Equal(0, http.Calls);
    }

    [Fact]
    public async Task Canjea_un_token_uuid_y_limpia_la_query()
    {
        var (guard, _) = Guard(req => req.RequestUri!.AbsolutePath.Contains("/adapter/")
            ? StubHandler.Json(SettingsBody())
            : StubHandler.Json(new { success = true, data = new { event_id = "ev-42", pass = Pass } }));

        var d = await guard.DecideAsync(Request(query: new Dictionary<string, string> { ["token"] = Token, ["sku"] = "7" }));

        Assert.Equal(DecisionType.Redirect, d.Type);
        Assert.Equal("/shop/entradas?sku=7", d.Location);
        Assert.Equal(Pass, d.Cookies!.Single(c => c.Name == "vq_pass_ev-42").Value);
    }

    [Fact]
    public async Task Un_token_que_no_es_uuid_ni_siquiera_toca_la_red()
    {
        var (guard, http) = Guard();

        var d = await guard.DecideAsync(Request(path: "/reset", query: new Dictionary<string, string> { ["token"] = "abc123" }));

        Assert.Equal(DecisionType.Allow, d.Type);
        Assert.Equal(0, http.VerifyCalls);
    }

    [Fact]
    public async Task Sin_pase_en_la_respuesta_del_verify_el_canje_falla()
    {
        // Escribir el token crudo como pase produciría una cookie que nunca
        // valida: el visitante volvería a la cola en la página siguiente.
        var (guard, _) = Guard(req => req.RequestUri!.AbsolutePath.Contains("/adapter/")
            ? StubHandler.Json(SettingsBody())
            : StubHandler.Json(new { success = true, data = new { event_id = "ev-42", pass = (string?)null, token = Token } }));

        var d = await guard.DecideAsync(Request(query: new Dictionary<string, string> { ["vq_token"] = Token }));

        Assert.Equal(DecisionType.Redirect, d.Type);
        Assert.Contains("/queue/ev-42", d.Location);
        Assert.DoesNotContain(d.Cookies!, c => c.Name == "vq_pass_ev-42");
    }

    [Fact]
    public async Task Un_3xx_del_verify_no_se_sigue_y_no_rompe()
    {
        var (guard, _) = Guard(req =>
        {
            if (req.RequestUri!.AbsolutePath.Contains("/adapter/")) return StubHandler.Json(SettingsBody());
            var r = new HttpResponseMessage(HttpStatusCode.Found);
            r.Headers.Location = new Uri("https://loop");
            return r;
        });

        var d = await guard.DecideAsync(Request(query: new Dictionary<string, string> { ["token"] = Token }));

        Assert.Equal(DecisionType.Redirect, d.Type);
        Assert.Contains("/queue/ev-42", d.Location);
    }

    [Fact]
    public async Task Ante_un_fallo_sirve_la_ultima_config_y_no_martilla_la_api()
    {
        var now = Now;
        var fail = false;
        var (guard, http) = Guard(
            req => fail ? throw new HttpRequestException("ECONNRESET") : StubHandler.Json(SettingsBody()),
            clock: () => now,
            settingsTtl: TimeSpan.FromSeconds(30));

        Assert.Equal(DecisionType.Redirect, (await guard.DecideAsync(Request())).Type);
        Assert.Equal(1, http.Calls);

        // Vencido y con la API caída: sigue protegiendo con la config anterior.
        now = now.AddSeconds(60);
        fail = true;
        Assert.Equal(DecisionType.Redirect, (await guard.DecideAsync(Request())).Type);
        Assert.Equal(2, http.Calls);

        // Dentro del backoff no vuelve a golpear la API.
        Assert.Equal(DecisionType.Redirect, (await guard.DecideAsync(Request())).Type);
        Assert.Equal(2, http.Calls);
    }

    [Fact]
    public async Task Sin_config_previa_un_fallo_deja_pasar_y_tampoco_martilla()
    {
        var (guard, http) = Guard(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        Assert.Equal(DecisionType.Allow, (await guard.DecideAsync(Request())).Type);
        Assert.Equal(DecisionType.Allow, (await guard.DecideAsync(Request())).Type);
        Assert.Equal(1, http.Calls);
    }

    [Fact]
    public async Task Sin_queue_url_no_hay_settings()
    {
        var (guard, _) = Guard(_ => StubHandler.Json(SettingsBody(queueUrl: null)));

        Assert.Equal(DecisionType.Allow, (await guard.DecideAsync(Request())).Type);
    }

    [Fact]
    public async Task Un_cookie_lifetime_raro_no_tira_abajo_los_settings()
    {
        var (guard, _) = Guard(_ => StubHandler.Json(SettingsBody(cookieLifetime: null)));

        var d = await guard.DecideAsync(Request(cookies: new Dictionary<string, string> { [QueuePass.CookieName("ev-42")] = Pass }));

        Assert.Equal(DecisionType.Allow, d.Type);
        Assert.Equal(QueueGuard.DefaultCookieLifetime, d.Renew!.MaxAgeSeconds);
    }

    [Fact]
    public async Task Un_request_abortado_no_cancela_la_carga_compartida()
    {
        // La primera request trae el ct cancelado; la carga de settings es
        // compartida y no debe heredarlo.
        var (guard, _) = Guard();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var d = await guard.DecideAsync(Request(), cts.Token);

        Assert.Equal(DecisionType.Redirect, d.Type);
    }

    [Theory]
    [InlineData("11111111-1111-1111-1111-111111111111", true)]
    [InlineData("11111111111111111111111111111111", false)]
    [InlineData("{11111111-1111-1111-1111-111111111111}", false)]
    [InlineData("abc", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Solo_un_uuid_con_guiones_es_token_de_cola(string? token, bool expected)
    {
        Assert.Equal(expected, QueueGuard.IsQueueToken(token));
    }

    [Theory]
    [InlineData(600L, 600)]
    [InlineData(0L, 600)]
    [InlineData(-5L, 600)]
    [InlineData(null, 600)]
    [InlineData(999_999L, 86_400)]
    public void Normaliza_cookie_lifetime_como_el_worker(long? value, int expected)
    {
        Assert.Equal(expected, QueueGuard.ResolveCookieLifetime(value));
    }
}
