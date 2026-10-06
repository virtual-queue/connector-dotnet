# VQueue.Connector (.NET)

Queue protection **inside your own ASP.NET Core app**. It is the server-side
equivalent of the JS adapter.

## Usage

```csharp
builder.Services.AddSingleton(new QueueGuard(new QueueGuardOptions
{
    Client = "orome",                                         // your company subdomain
    PrivateKey = builder.Configuration["VQueue:PrivateKey"]!, // never hardcode it
}));

var app = builder.Build();
app.UseVQueue();   // before the endpoints you want to protect
```

Without ASP.NET, use the guard directly:

```csharp
var decision = await guard.DecideAsync(new QueueRequest(path, query, cookies, method));
```

## What it does

1. **Cheap bypass** — assets, `/api/`, WebSockets, and methods other than GET/HEAD.
   A 302 on a POST would lose the checkout body.
2. **Return from the queue** — exchanges `?vq_token=`, issues `vq_pass_<event_id>`,
   and returns to the original destination. Your site's own `?token=` is never
   hijacked.
3. **ACLs** — by priority, first match wins.
4. **Pass** — verifies the HMAC **offline** with the `private_key`; it doesn't call
   VirtualQueue on every request.
5. **Sliding renewal** — done in a single pass. Lambda@Edge needs a second function
   for this; here the middleware touches the response before it goes out.

Everything fails open: with no settings, no API, or an incomplete config, the
visitor gets through.

## Configuration

| Option | Default | What it is |
|---|---|---|
| `Client` | — | Your company subdomain in VirtualQueue |
| `PrivateKey` | — | Your `private_key`; verifies the pass offline |
| `AdminHost` | `clients.virtual-queue.com` | Where to download the ACLs from |
| `SettingsTtl` | 30s | Process-level ACL cache |
| `SecureCookies` | `true` | `false` only for development on `http://localhost` |

## Tests

```bash
dotnet test tests/VQueue.Connector.Tests/VQueue.Connector.Tests.csproj
```
