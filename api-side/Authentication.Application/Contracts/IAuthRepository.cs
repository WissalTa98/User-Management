using Authentication.Domain.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Application.IRepositories
{
    public interface IAuthRepository
    {
        Task<TokenModel> Login(LoginModel model);
        Task<Response> RegisterUser(RegisterModel model);
        Task<Response> RegisterAdmin(RegisterModel model);
        Task<TokenModel> RefreshToken(TokenModel tokenModel);
        public JwtSecurityToken CreateToken(List<Claim> authClaims);
       // void GenerateRefreshToken();
        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);

    }
}
