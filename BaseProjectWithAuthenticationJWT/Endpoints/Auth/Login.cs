using BaseProjectWithAuthenticationJWT.Models.Entities;
using BaseProjectWithAuthenticationJWT.Models;
using BaseProjectWithAuthenticationJWT.Services;
using FluentValidation;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace BaseProjectWithAuthenticationJWT.Endpoints.Auth
{
    public static class Login
    {
        public static async Task<IResult> HandlerAsync(LoginRequest req, AppDbContext context, IValidator<LoginRequest> validator, IPasswordHasher<Users> hash, TokenManager tokenManager)
        {
            var validation = await validator.ValidateAsync(req);

            if (!validation.IsValid)
            {
                return Results.ValidationProblem(validation.ToDictionary());
            }

            var user = await context.Users.FirstOrDefaultAsync(x => x.Username == req.Username);

            if (user == null)
            {
                return Results.NotFound();
            }

            var validationPassword = hash.VerifyHashedPassword(user, user.Password, req.Password);

            if (PasswordVerificationResult.Failed == validationPassword)
            {
                return Results.Unauthorized();
            }

            var refreshToken = tokenManager.GenerateRefreshToken();
            var accesToken = tokenManager.GenerateAccessToken(user);

            user.RefreshToken = refreshToken;
            user.DtExpirationToken = DateTime.Now.AddMinutes(400);

            var response = new LoginResponse(refreshToken, accesToken);

            await context.SaveChangesAsync();

            return Results.Ok(response);
        }
    }

    public class LoginValidator : AbstractValidator<LoginRequest>
    {
        public LoginValidator()
        {
            RuleFor(x => x.Username).NotEmpty().NotNull();
            RuleFor(x => x.Password).NotEmpty().NotNull();
        }
    }
    public record LoginRequest(string Username, string Password);
    public record LoginResponse(string RefreshToken, string AccessToken);
}
