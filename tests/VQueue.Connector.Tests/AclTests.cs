using VQueue.Connector;
using Xunit;

namespace VQueue.Connector.Tests;

public class AclTests
{
    private static AclRule Rule(string action, string pattern, string type, int? priority, bool enabled = true) =>
        new() { Action = action, Pattern = pattern, PatternType = type, Priority = priority, Enabled = enabled };

    [Fact]
    public void Gana_la_regla_de_mayor_prioridad()
    {
        var rules = Acl.Sort(new[]
        {
            Rule("redirect_to_queue", "/shop", "prefix", 0),
            Rule("bypass", "/shop/ayuda", "exact", -1),
        });

        Assert.Equal("bypass", Acl.FirstMatch(rules, "/shop/ayuda")!.Action);
        Assert.Equal("redirect_to_queue", Acl.FirstMatch(rules, "/shop/entradas")!.Action);
    }

    [Fact]
    public void Descarta_las_reglas_deshabilitadas()
    {
        var rules = Acl.Sort(new[] { Rule("redirect_to_queue", "/shop", "prefix", 0, enabled: false) });

        Assert.Empty(rules);
        Assert.Null(Acl.FirstMatch(rules, "/shop"));
    }

    [Fact]
    public void Una_regla_sin_priority_va_al_final()
    {
        var rules = Acl.Sort(new[]
        {
            Rule("a", "/x", "prefix", null),
            Rule("b", "/x", "prefix", 5),
        });

        Assert.Equal("b", rules[0].Action);
    }

    [Fact]
    public void El_glob_no_trata_el_punto_como_metacaracter()
    {
        var rule = Rule("x", "/shop/*.html", "glob", 0);

        Assert.True(Acl.Matches(rule, "/shop/entradas.html"));
        Assert.False(Acl.Matches(rule, "/shop/entradasXhtml"));
    }

    [Theory]
    [InlineData("/shop/app.css", true)]
    [InlineData("/shop/app.mjs", true)]
    [InlineData("/img/foto.avif", true)]
    // `.json` NO es asset: lo usan endpoints dinámicos que hay que proteger.
    [InlineData("/shop/products.json", false)]
    [InlineData("/shop/entradas", false)]
    public void Reconoce_los_assets(string path, bool expected)
    {
        Assert.Equal(expected, Acl.IsAsset(path));
    }

    [Fact]
    public void Un_pattern_type_desconocido_no_matchea()
    {
        Assert.False(Acl.Matches(Rule("x", "/shop", "regex", 0), "/shop"));
    }
}

public class SafeTargetTests
{
    [Theory]
    [InlineData("https://malicioso.com")]
    [InlineData("//malicioso.com")]
    [InlineData("/ok\r\nSet-Cookie: x=1")]
    [InlineData("relativo")]
    [InlineData("")]
    [InlineData(null)]
    public void No_abre_un_open_redirect(string? target)
    {
        Assert.Null(QueueGuard.SafeTarget(target));
    }

    [Fact]
    public void Acepta_un_path_propio()
    {
        Assert.Equal("/shop/entradas?fila=3", QueueGuard.SafeTarget("/shop/entradas?fila=3"));
    }
}
