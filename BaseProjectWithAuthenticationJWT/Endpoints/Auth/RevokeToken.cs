using BaseProjectWithAuthenticationJWT.Models;
using Microsoft.EntityFrameworkCore;

namespace BaseProjectWithAuthenticationJWT.Endpoints.Auth
{
    public static class RevokeToken
    {
        public static async Task<IResult> HandlerAsync(AppDbContext context, RevokeTokenRequest req)
        {
            var user = await context.Users.FirstOrDefaultAsync(x => x.RefreshToken == req.RefreshToken);

            if (user == null)
            {
                return Results.BadRequest("Invalid Token");
            }

            user.DtExpirationToken = null;
            user.RefreshToken = null;

            await context.SaveChangesAsync();

            return Results.Ok();
        }
    }

    public record RevokeTokenRequest(string RefreshToken);
}
