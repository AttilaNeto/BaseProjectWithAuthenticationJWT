using BaseProjectWithAuthenticationJWT.Models.Entities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace BaseProjectWithAuthenticationJWT.Services
{
    public class TokenManager
    {
        private IConfiguration config;

        public TokenManager(IConfiguration configuration)
        {
            config = configuration;
        }

        public string GenerateAccessToken(Users user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:secretKey"] + "ce85b"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("user_id", user.IdUser.ToString()),
                    new Claim("name", user.Name),
                }),
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

            return refreshToken;
        }

        public async Task<ValidateToken> AccessTokenIsValidAsync(string token)
        {

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:secretKey"] + "ce85b"));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero,
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            var validate = await tokenHandler.ValidateTokenAsync(token, tokenValidationParameters);

            if (!validate.IsValid)
            {
                return new ValidateToken(false);
            }

            var idUsuario = validate.Claims.FirstOrDefault(c => c.Key == "user_id").Value;

            int? idUser = null;

            if (idUsuario != null)
            {
                if (int.TryParse(idUsuario.ToString(), out int parsedId))
                {
                    idUser = parsedId;
                }
            }
            return new ValidateToken(true, idUser);

        }

        public record ValidateToken(bool IsValid, int? IdUser = null);



    }
}
