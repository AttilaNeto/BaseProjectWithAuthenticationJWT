using Carter;

namespace BaseProjectWithAuthenticationJWT.Endpoints.Auth
{
    public class Auth : ICarterModule
    {
        public void AddRoutes(IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("api/" + nameof(Auth)).WithDisplayName(nameof(Auth));

            group.MapPost("/register", Register.HandlerAsync)
                .AllowAnonymous();

            group.MapPost("/login", Login.HandlerAsync)
                .Produces<LoginResponse>(200)
                .AllowAnonymous();

            group.MapPost("/refresh-token", RefreshToken.HandlerAsync)
                .AllowAnonymous();

            group.MapPost("/revoke-token", RevokeToken.HandlerAsync)
                .RequireAuthorization();

        }
    }
}
