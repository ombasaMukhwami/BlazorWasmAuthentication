using BlazorWasmAuthentication.Shared;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BlazorWasmAuthentication.Server.Authentication;

public class JwtAuthenticationManager
{
    

    public UserAccountService _userAccountService;
    public JwtAuthenticationManager(UserAccountService userAccountService)
    {
        _userAccountService = userAccountService;
    }

    public UserSession? GenerateJwtToken(string userName, string password)
    {
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
            return null;

        // Validating the user credentials
        var userAccount = _userAccountService.GetUserAccountByUserName(userName);
        if (userAccount is null)// || userAccount.Password != null)
            return null;
        /* Generate JWT Token */
        var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(Constants.JWT_TOKEN_VALIDITY_MINS);
        var tokenKey = Encoding.UTF8.GetBytes(Constants.JWT_SECURITY_KEY);
        var claimsIdentity = new ClaimsIdentity(new List<Claim>
        {
            new Claim(ClaimTypes.Name, userName),
            new Claim(ClaimTypes.Role, userAccount.Role)
        });

        var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature);

        var securityTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = claimsIdentity,
            Expires = tokenExpiryTimeStamp,
            SigningCredentials = signingCredentials             
        };

        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
        var token = jwtSecurityTokenHandler.WriteToken(securityToken);

        var userSession = new UserSession
        {
            UserName = userName,
            Role = userAccount.Role,
            Token = token,
            ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds
        };

        return userSession;
    }
}