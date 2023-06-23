using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtTest.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class AsymmetricController : ControllerBase
{
    private readonly IConfiguration configuration;

    public AsymmetricController(IConfiguration configuration)
    {
        this.configuration = configuration; // Needed to access the stored  JWT secret key
    }

    [HttpPost]
    public IActionResult GenerateTokenAsymmetric()
    {
        string privateKeyText = System.IO.File.ReadAllText("test.key.pem");
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyText);

        var signingCredentials = new SigningCredentials(
            key: new RsaSecurityKey(rsa),
            algorithm: SecurityAlgorithms.RsaSha256 // Important to use RSA version of the SHA algo 
        );

        DateTime jwtDate = DateTime.Now;

        var jwt = new JwtSecurityToken(
            audience: "jwt-test",
            issuer: "jwt-test",
            claims: new Claim[] { new Claim(ClaimTypes.NameIdentifier, "some-username") },
            notBefore: jwtDate,
            expires: jwtDate.AddSeconds(10),
            signingCredentials: signingCredentials
        );

        string token = new JwtSecurityTokenHandler().WriteToken(jwt);

        return Ok(new
        {
            jwt = token,
            unixTimeExpiresAt = new DateTimeOffset(jwtDate).ToUnixTimeMilliseconds(),
        });
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "Asymmetric")] // Use the "Asymmetric" authentication scheme
    public IActionResult ValidateTokenAsymmetric()
    {
        return Ok();
    }
}