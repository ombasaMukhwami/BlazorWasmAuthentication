using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlazorWasmAuthentication.Shared
{
    public static class Constants
    {
        public const string USER_SESSION_KEY = "UserSession";
        public const string JWT_AUTH = "JwtAuth";
        public const string JWT_SECURITY_KEY = "yPkCqn4kSWLtaJwXvN2jGzpQRyTZ3gdXkt7FeBJP";
        public const int JWT_TOKEN_VALIDITY_MINS = 20;

        public const string ADMINISTRATOR_ROLE = "Administrator";
        public const string USER_ROLE = "User";

        public const string BEARER = "Bearer";
    }
}
