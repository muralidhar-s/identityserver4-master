using System.Threading.Tasks;
using bluenumberis.STS.Identity.DTO.HumanId;

namespace bluenumberis.STS.Identity.Services.Abstract
{
    public interface IHumanIdService
    {
        Task<HumanIdResponse> RequestOTP(string countryCode, string phone);
        Task<HumanIdResponse> Login(HumanIdLoginRequest dto);
        Task<HumanIdResponse> VerifyExchangeToken(HumanIdExchangeToken dto);
    }
}