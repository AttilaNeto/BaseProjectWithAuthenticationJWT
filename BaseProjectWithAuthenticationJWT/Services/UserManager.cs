using BaseProjectWithAuthenticationJWT.Models;
using System.Security.Claims;

namespace BaseProjectWithAuthenticationJWT.Services
{
    public class UserManager
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public UserManager(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public UserClaimsLogin? GetDataUser()
        {
            if (_httpContextAccessor.HttpContext is null)
            {
                return null;
            }

            var claims = _httpContextAccessor.HttpContext.User.Claims;

            var userData = new UserClaimsLogin
            {
                IdUser = claims.FirstOrDefault(c => c.Type == "user_id")?.Value,
                Name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value,
                Role = claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value,
            };

            return userData;
        }
        public int? GetIdUser()
        {
            if (_httpContextAccessor.HttpContext is null)
            {
                return null;
            }

            var claims = _httpContextAccessor.HttpContext.User.Claims;

            var user_idClaim = claims.FirstOrDefault(c => c.Type == "user_id")?.Value;

            int? idUser = null;

            if (user_idClaim != null)
            {
                if (int.TryParse(user_idClaim, out int parsedId))
                {
                    idUser = parsedId;
                }
            }
            return idUser;
        }
    }
}
