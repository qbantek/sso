using SSO.Annotations;

namespace SSO.Models
{
    [UsedImplicitly]
    public class ServiceResult
    {
        public ResultCodeTypes Result { get; set; }

        public string ResultString { get; set; }

        public object ResultObject { get; set; }
    }
}