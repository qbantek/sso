using System;
using SSO.Annotations;

namespace SSO.Models
{
    [UsedImplicitly]
    public class SingleSignOnRegistrationResponse
    {
        public String UserToken { get; set; }
    }
}