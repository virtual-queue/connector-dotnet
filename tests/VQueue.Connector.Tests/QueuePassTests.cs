using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VQueue.Connector;
using Xunit;

namespace VQueue.Connector.Tests;

/// <summary>
/// VECTOR DE INTEROPERABILIDAD
///
/// Este pase NO lo generó este código: lo firmó la implementación Elixir real
/// (VQueue.Lines.QueuePass.sign/4). Es el MISMO vector que usan el core JS y el
/// SDK de PHP, así que las cuatro implementaciones quedan ancladas al mismo
/// formato. Si alguna deriva, este test se cae.
///
///   secret:  "test-private-key-abc123"
///   iat/exp: 1700000000 / 1700003600
///   evento:  "ev-42"
/// </summary>
public class QueuePassTests
{
    private const string Pass =
        "eyJlIjoiZXYtNDIiLCJleHAiOjE3MDAwMDM2MDAsImlhdCI6MTcwMDAwMDAwMCwidCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSJ9"
        + ".AjaVlbsXru7V8GOJuhEV2doxd3W1-dQlEVTi5BEnNco";

    private const string Secret = "test-private-key-abc123";
    private static readonly DateTimeOffset BeforeExp = DateTimeOffset.FromUnixTimeSeconds(1_700_000_100);
    private static readonly DateTimeOffset AfterExp = DateTimeOffset.FromUnixTimeSeconds(1_700_003_601);

    [Fact]
    public void Acepta_un_pase_firmado_por_vqueue()
    {
        var result = QueuePass.Verify(Pass, Secret, BeforeExp);

        Assert.True(result.Ok);
        Assert.Equal("ev-42", result.EventId);
        Assert.Equal("11111111-1111-1111-1111-111111111111", result.LineId);
        Assert.Equal(1_700_003_600, result.Exp);
    }

    [Fact]
    public void Lo_rechaza_cuando_vencio()
    {
        var result = QueuePass.Verify(Pass, Secret, AfterExp);

        Assert.False(result.Ok);
        Assert.Equal("expired", result.Reason);
    }

    [Fact]
    public void Lo_rechaza_con_otro_secreto()
    {
        Assert.Equal("bad_signature", QueuePass.Verify(Pass, "otro-secreto", BeforeExp).Reason);
    }

    [Fact]
    public void Rechaza_un_payload_alterado()
    {
        var parts = Pass.Split('.', 2);
        var json = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
        // Extender el vencimiento 10 años: la firma deja de cerrar.
        var tampered = json.Replace("1700003600", "2000000000");
        var forged = Base64UrlEncode(Encoding.UTF8.GetBytes(tampered));

        Assert.Equal("bad_signature", QueuePass.Verify($"{forged}.{parts[1]}", Secret, BeforeExp).Reason);
    }

    [Fact]
    public void Rechaza_una_firma_recortada()
    {
        var parts = Pass.Split('.', 2);
        var truncated = parts[1][..^1];

        Assert.Equal("bad_signature", QueuePass.Verify($"{parts[0]}.{truncated}", Secret, BeforeExp).Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("sin-punto")]
    [InlineData(".solo-firma")]
    [InlineData("solo-payload.")]
    [InlineData(null)]
    public void Rechaza_formatos_rotos_sin_lanzar(string? bad)
    {
        Assert.False(QueuePass.Verify(bad, Secret, BeforeExp).Ok);
    }

    [Fact]
    public void Rechaza_un_payload_bien_firmado_pero_sin_exp()
    {
        var encoded = Base64UrlEncode(Encoding.UTF8.GetBytes("""{"t":"x","e":"ev-42"}"""));
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(Secret));
        var signature = Base64UrlEncode(hmac.ComputeHash(Encoding.UTF8.GetBytes(encoded)));

        Assert.Equal("malformed", QueuePass.Verify($"{encoded}.{signature}", Secret, BeforeExp).Reason);
    }

    [Fact]
    public void Sin_secreto_no_valida_nada()
    {
        Assert.False(QueuePass.Verify(Pass, "", BeforeExp).Ok);
    }

    [Fact]
    public void Acepta_el_pase_del_evento_consultado()
    {
        var cookies = new Dictionary<string, string> { [QueuePass.CookieName("ev-42")] = Pass };

        Assert.True(QueuePass.ValidFor(cookies, "ev-42", Secret, BeforeExp).Ok);
    }

    [Fact]
    public void No_admite_al_evento_b_con_el_pase_del_evento_a()
    {
        // La cookie del evento B contiene un pase válido... pero de otro evento.
        var cookies = new Dictionary<string, string> { [QueuePass.CookieName("ev-99")] = Pass };

        Assert.Equal("event_mismatch", QueuePass.ValidFor(cookies, "ev-99", Secret, BeforeExp).Reason);
    }

    [Fact]
    public void Informa_cuando_no_hay_cookie()
    {
        var empty = new Dictionary<string, string>();

        Assert.Equal("absent", QueuePass.ValidFor(empty, "ev-42", Secret, BeforeExp).Reason);
    }

    private static string Base64UrlEncode(byte[] raw) =>
        Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string encoded)
    {
        var padded = encoded.Replace('-', '+').Replace('_', '/');
        padded += (encoded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }
}
