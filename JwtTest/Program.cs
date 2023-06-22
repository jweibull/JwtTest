using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();


// Configure validation of regular JWT signed with a symmetric key
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme) // Set default to 'Bearer'
    .AddJwtBearer(options => { // Configure how the Bearer token is validated
        var symmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Symmetric:Key"]!));
        options.IncludeErrorDetails = true; // <- great for debugging
        
        // Configure the actual Bearer validation
        options.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = symmetricKey,
            ValidAudience = "jwt-test",
            ValidIssuer = "jwt-test",
            RequireSignedTokens = true,
            RequireExpirationTime = true, // <- JWTs are required to have "exp" property set
            ValidateLifetime = true, // <- the "exp" will be validated
            ValidateAudience = true,
            ValidateIssuer = true,
        };
    });

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
