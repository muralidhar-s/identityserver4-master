using System.Threading.Tasks;
using bluenumberis.STS.Identity.DTO.Issuer;

namespace bluenumberis.STS.Identity.Services.Abstract
{
    public interface IIssuerService
    {
        Task<IssuerResponse> GetOTP(string countryCode, string phone, bool login);
        Task<IssuerResponse> VerifyLoginOTP(LoginOTPRequest dto);
        Task<IssuerResponse> VerifyRegisterOTP(RegisterOTPRequest dto);
        Task<IssuerRegisterResponse> RegisterPhone(RegisterBlueNumberRequest dto);
    }
}