using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Jwt.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // bu sayede sadece authorize olmuş kullanıcı end pointlere erişebilir şemasız kullanılamaz.
    public class AuthController : ControllerBase
    {
        string signingKey = "BuBenimSigningKey"; // bizim secret key'imiz

        [HttpGet]
        public string Get(string userName, string password) // burada bir token üreteceğiz ve karşı tarafa vereceğiz.
        {
            //payload yük taşıyıcı sistemimiz. Data içerebilir
            var claims = new[]
            {
                new Claim(ClaimTypes.Name,userName),
                new Claim(JwtRegisteredClaimNames.Email,userName)
            };
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(

                issuer: "umutcanbuyuker",
                audience: "BuBenimKullandigimAudienceDegeri",
                claims: claims,
                expires: DateTime.Now.AddDays(15),
                notBefore: DateTime.Now,
                signingCredentials: credentials
                //claim verilerileri tuttuğum daha sonra ayıklayabileceğim yer
                ); //verilerimizi JwtSecurityToken'da saklayacağız.

            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return token;
        }
        [HttpGet("ValidateToken")]
        public bool ValidateToken(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            try
            {
                JwtSecurityTokenHandler handler = new();
                handler.ValidateToken(token, new TokenValidationParameters() 
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                },out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken; 
                var claims = jwtToken.Claims;
                return true;
            }
            catch (Exception)
            {

                return false;
            }
        }
    }
}
