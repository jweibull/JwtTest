using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtTest.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class SymmetricController : ControllerBase
{
    private readonly IConfiguration configuration;

    public SymmetricController(IConfiguration configuration)
    {
        this.configuration = configuration; // Needed to access the stored  JWT secret key
    }

    [HttpPost]
    public IActionResult GenerateToken()
    {
        var key = configuration["Jwt:Symmetric:Key"]!;
        var signingCredentials = new SigningCredentials(
            key: new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            algorithm: SecurityAlgorithms.HmacSha256);

        DateTime jwtDate = DateTime.Now;

        var jwt = new JwtSecurityToken(
            audience: "jwt-test", // must match the audience in AddJwtBearer()
            issuer: "jwt-test", // must match the issuer in AddJwtBearer()

            // Add whatever claims you'd want the generated token to include
            claims: new List<Claim> { new Claim(ClaimTypes.NameIdentifier, "some-username") },
            notBefore: jwtDate,
            expires: jwtDate.AddSeconds(30), // Should be short lived. For logins, it's may be fine to use 24h

            // Provide a cryptographic key used to sign the token.
            // When dealing with symmetric keys then this must be
            // the same key used to validate the token.
            signingCredentials: signingCredentials
        );

        // Generate the actual token as a string
        string token = new JwtSecurityTokenHandler().WriteToken(jwt);

        // Return some agreed upon or documented structure.
        return Ok(new
        {
            jwt = token,
            // Even if the expiration time is already a part of the token, it's common to be 
            // part of the response body.
            unixTimeExpiresAt = new DateTimeOffset(jwtDate).ToUnixTimeMilliseconds()
        });
    }

    [HttpGet]
    [Authorize] // Uses the default configured scheme, in this case "Bearer".
    public IActionResult ValidateToken()
    {
        return Ok();
    }
}
