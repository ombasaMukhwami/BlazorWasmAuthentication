using Blazored.SessionStorage;
using BlazorWasmAuthentication.Client.Extensions;
using BlazorWasmAuthentication.Shared;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace BlazorWasmAuthentication.Client.Authentication;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly ISessionStorageService _sessionStorageService;
    private ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());

    public CustomAuthenticationStateProvider(ISessionStorageService sessionStorageService)
    {
        _sessionStorageService = sessionStorageService;
    }
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var userSession = await _sessionStorageService.ReadEncryptedItemAsync<UserSession>(Constants.USER_SESSION_KEY);
            if (userSession == null) return await Task.FromResult(new AuthenticationState(_anonymous));
            var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Name, userSession.UserName),
                new Claim(ClaimTypes.Role, userSession.Role)
            }, Constants.JWT_AUTH));

            return await Task.FromResult(new AuthenticationState(claimsPrincipal));
        }
        catch (Exception e)
        {

            return await Task.FromResult(new AuthenticationState(_anonymous));
        }
    }

    public async Task UpdateAuthenticationState(UserSession? userSession)
    {
        ClaimsPrincipal? claimsPrincipal = null;
        if (userSession is not null)
        {
            claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Name, userSession.UserName),
                new Claim(ClaimTypes.Role, userSession.Role)
            }));

            userSession.ExpiryTimeStamp = DateTime.Now.AddSeconds(userSession.ExpiresIn);
            await _sessionStorageService.SaveItemEncryptedAsync(Constants.USER_SESSION_KEY, userSession);
        }
        else
        {
            claimsPrincipal = _anonymous;
            await _sessionStorageService.RemoveItemAsync(Constants.USER_SESSION_KEY);
        }

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
    }

    public async Task<string> GetToken()
    {
        var result = string.Empty;

        try
        {
            var userSession = await _sessionStorageService.ReadEncryptedItemAsync<UserSession>(Constants.USER_SESSION_KEY);
            if (userSession is not null && DateTime.Now < userSession.ExpiryTimeStamp)
                result = userSession.Token;
        }
        catch (Exception _)
        {

            throw;
        }
        return result;

    }
}
