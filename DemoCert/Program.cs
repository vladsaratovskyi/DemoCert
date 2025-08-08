using System.Security.Cryptography.X509Certificates;
using DemoCert;

var builder = WebApplication.CreateBuilder(args);


var rootCa = new X509Certificate2(builder.Environment.ContentRootFileProvider
    .GetFileInfo("certs/yourcert.cert").PhysicalPath);

builder.Services.AddHttpClient("trusted-backend").ConfigurePrimaryHttpMessageHandler(() => HandlerFactory.CreateHandlerWithCustomRoot(rootCa));

var app = builder.Build();

app.MapGet("/call-api", async (IHttpClientFactory httpFactory) =>
{
    var client = httpFactory.CreateClient("trusted-backend");
    var response = await client.GetStringAsync("https://yourservice.com");
    return Results.Text(response);
});

app.Run();
