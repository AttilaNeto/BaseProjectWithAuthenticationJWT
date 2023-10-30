using BaseProjectWithAuthenticationJWT.Models;
using BaseProjectWithAuthenticationJWT.Services;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BaseProjectWithAuthenticationJWT.Endpoints.Auth
{
    public static class RefreshToken
    {
        public async static Task<IResult> HandlerAsync([FromBody] RefreshTokenRequest req, AppDbContext context, TokenManager tokenManager)
        {
            var userToken = await tokenManager.AccessTokenIsValidAsync(req.AccessToken);

            if (!userToken.IsValid || userToken.IdUser is null)
            {
                return Results.BadRequest("Invalid Token");
            }

            var user = await context.Users.FirstOrDefaultAsync(x => x.IdUser == userToken.IdUser && x.RefreshToken == req.RefreshToken);

            if (user == null || user.DtExpirationToken < DateTime.Now)
            {
                return Results.Unauthorized();
            }

            var newAccessToken = tokenManager.GenerateAccessToken(user);
            var newRefreshToken = tokenManager.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.DtExpirationToken = DateTime.Now.AddMinutes(400);

            await context.SaveChangesAsync();

            return Results.Ok(new RefreshResponse(newRefreshToken, newAccessToken));

        }

    }


    public record RefreshTokenRequest(string RefreshToken, string AccessToken);
    public record RefreshResponse(string RefreshToken, string AccessToken);
    public class RefreshTokenValidator : AbstractValidator<RefreshTokenRequest>
    {
        public RefreshTokenValidator()
        {
            RuleFor(x => x.RefreshToken).NotEmpty();
        }
    }
}
