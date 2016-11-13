using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Security.OAuth;

namespace WebApiAuthorizationTest
{
    public class MyAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated(); //client validated
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            if (context.UserName == "Admin" && context.Password == "Admin")
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                identity.AddClaim(new Claim("username", "Admin"));
                identity.AddClaim(new Claim(ClaimTypes.Name, "Speedyjet"));
                context.Validated(identity);
            }
            else if (context.UserName == "User" && context.Password == "user")
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, "User"));
                identity.AddClaim(new Claim("username", "Admin"));
                identity.AddClaim(new Claim(ClaimTypes.Name, "SpeedyUser"));
                context.Validated(identity);
            }
            else
            {
                context.SetError("invalid grant","provided username and password are incorrect");
                return;
            }
        }
    }
}