using System.Security.Cryptography;

namespace LocalVault.Desktop;

internal static class HelloPublicKeyProtector
{
    internal static RSAParameters ReadPublicKey(RSA systemKey)
    {
        try
        {
            var parameters = systemKey.ExportParameters(includePrivateParameters: false);
            if (parameters.Modulus is not { Length: 256 } || (parameters.Modulus[0] & 0x80) == 0 ||
                parameters.Exponent is not { Length: > 0 and <= 4 } ||
                parameters.D is not null || parameters.P is not null || parameters.Q is not null ||
                parameters.DP is not null || parameters.DQ is not null || parameters.InverseQ is not null)
                throw new CryptographicException();
            return parameters;
        }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.ExportPublicKey, error); }
    }
}
