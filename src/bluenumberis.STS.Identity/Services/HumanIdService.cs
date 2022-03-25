using bluenumberis.STS.Identity.Constants;
using bluenumberis.STS.Identity.DTO.HumanId;
using bluenumberis.STS.Identity.Services.Abstract;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace bluenumberis.STS.Identity.Services
{
    public class HumanIdService : IHumanIdService
    {
        #region Private Variables

        private readonly string _mobileClientId;
        private readonly string _mobileClientSecret;
        private readonly string _serverClientId;
        private readonly string _serverClientSecret;
        private readonly HttpClient _httpClient;
        
        #endregion

        #region Constructor

        public HumanIdService(HttpClient httpClient,
            IConfiguration config)
        {
            _httpClient = httpClient
                ?? throw new ArgumentNullException(nameof(httpClient));

            _mobileClientId = config["HumanId:Mobile:ClientId"];
            _mobileClientSecret = config["HumanId:Mobile:ClientSecret"];
            _serverClientId = config["HumanId:Server:ClientId"];
            _serverClientSecret = config["HumanId:Server:ClientSecret"];
        }
        
        #endregion

        #region Public Methods

        public async Task<HumanIdResponse> RequestOTP(string countryCode, string phone)
        {
            try
            {
                HumanIdOTPRequest dto = new HumanIdOTPRequest()
                {
                    countryCode = countryCode.Replace("+", string.Empty),
                    phone = phone
                };
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                content.Headers.Add("client-id", _mobileClientId);
                content.Headers.Add("client-secret", _mobileClientSecret);
                var httpResponse = await _httpClient.PostAsync("/v0.0.3/mobile/users/login/request-otp", content);

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<HumanIdResponse>(jsonString);

                return data;
            }
            catch(Exception ex)
            {
                throw ex;
            }
        }

        public async Task<HumanIdResponse> Login(HumanIdLoginRequest dto)
        {
            try
            {
                dto.countryCode = dto.countryCode.Replace("+", string.Empty);
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                content.Headers.Add("client-id", _mobileClientId);
                content.Headers.Add("client-secret", _mobileClientSecret);
                var httpResponse = await _httpClient.PostAsync("/v0.0.3/mobile/users/login", content);

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<HumanIdResponse>(jsonString);

                return data;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<HumanIdResponse> VerifyExchangeToken(HumanIdExchangeToken dto)
        {
            try
            {
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                content.Headers.Add("client-id", _serverClientId);
                content.Headers.Add("client-secret", _serverClientSecret);
                var httpResponse = await _httpClient.PostAsync("/v0.0.3/server/users/verifyExchangeToken", content);

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<HumanIdResponse>(jsonString);

                return data;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #endregion
    }
}