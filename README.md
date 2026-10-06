# VQueue.Connector (.NET)

Protección de cola **dentro de la app ASP.NET Core del cliente**. Equivalente
server-side del JS adapter.

## Uso

```csharp
builder.Services.AddSingleton(new QueueGuard(new QueueGuardOptions
{
    Client = "orome",                                        // subdominio
    PrivateKey = builder.Configuration["VQueue:PrivateKey"]!, // nunca hardcodeada
}));

var app = builder.Build();
app.UseVQueue();   // antes de los endpoints que querés proteger
```

Sin ASP.NET, el guard se usa directo:

```csharp
var decision = await guard.DecideAsync(new QueueRequest(path, query, cookies, method));
```

## Qué hace

1. **Bypass barato** — assets, `/api/`, WebSockets y métodos que no son GET/HEAD.
   Un 302 sobre un POST perdería el body del checkout.
2. **Vuelta de la cola** — canjea `?vq_token=`, emite `vq_pass_<event_id>` y
   vuelve al destino original. Un `?token=` propio del sitio no se secuestra.
3. **ACLs** — por prioridad, primera gana.
4. **Pase** — verifica el HMAC **offline** con la `private_key`; no llama a
   VQueue en cada request.
5. **Renovación deslizante** — resuelta en una sola pasada. Lambda@Edge necesita
   una segunda función para esto; acá el middleware toca la respuesta antes de
   que salga.

Todo falla abierto: sin settings, sin API o con config incompleta, el visitante
pasa.

## Configuración

| Opción | Default | Qué es |
|---|---|---|
| `Client` | — | Subdominio de la compañía en VQueue |
| `PrivateKey` | — | `private_key`; verifica el pase offline |
| `AdminHost` | `clients.virtual-queue.com` | De dónde bajar las ACLs |
| `SettingsTtl` | 30s | Cache de ACLs a nivel proceso |
| `SecureCookies` | `true` | `false` solo para desarrollo en `http://localhost` |

## Tests

```bash
dotnet test tests/VQueue.Connector.Tests/VQueue.Connector.Tests.csproj
```
