using System;
using SSO.Annotations;

namespace SSO.Models
{
    [UsedImplicitly]
    public class SingleSignOnLoginResponse
    {
        public String RedirectToUrl { get; set; }
        public String SessionToken { get; set; }
    }
}