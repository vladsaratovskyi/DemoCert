using System.Security.Cryptography.X509Certificates;

namespace DemoCert;

public static class HandlerFactory
{
    public static HttpMessageHandler CreateHandlerWithCustomRoot(X509Certificate2 rootCa, params X509Certificate2[] intermediates)
    {
        var handler = new HttpClientHandler
        {
            // Keep certificate validation ON, but point it at our custom trust store
            ServerCertificateCustomValidationCallback = (req, cert, chain, errors) =>
            {
                // Use a fresh policy each time to avoid cross-request contamination
                var policy = chain.ChainPolicy;
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.Clear();
                policy.CustomTrustStore.Add(rootCa);
                foreach (var inter in intermediates)
                    policy.CustomTrustStore.Add(inter);

                // Optional, but common for private PKIs
                policy.RevocationMode = X509RevocationMode.NoCheck;  // or Online if you have CRL/OCSP
                policy.VerificationFlags = X509VerificationFlags.NoFlag;

                // Rebuild the chain against our store
                chain = new X509Chain { ChainPolicy = policy };
                return cert != null && chain.Build(cert);
            }
        };

        return handler;
    }
}