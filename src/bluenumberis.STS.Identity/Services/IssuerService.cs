using BlueNumber.Issuer.Api.DTO;
using bluenumberis.STS.Identity.Constants;
using bluenumberis.STS.Identity.DTO.Issuer;
using bluenumberis.STS.Identity.Services.Abstract;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace bluenumberis.STS.Identity.Services
{
    public class IssuerService : IIssuerService
    {
        #region Private Variables

        private readonly HttpClient _httpClient;
        
        #endregion

        #region Constructor

        public IssuerService(HttpClient httpClient,
            IConfiguration config)
        {
            _httpClient = httpClient
                ?? throw new ArgumentNullException(nameof(httpClient));
        }
        
        #endregion

        #region Public Methods

        public async Task<IssuerResponse> GetOTP(string countryCode, string phone, bool login)
        {
            try
            {
                var dto = new
                {
                    mobile = countryCode + phone
                };
                string endpoint = login ? "/api/v1/Auth/Login" : "/api/v1/Register/Mobile";
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                var httpResponse = await _httpClient.PostAsync(endpoint, content);

                if (!httpResponse.IsSuccessStatusCode)
                {
                    var errorString = await httpResponse.Content.ReadAsStringAsync();
                    var apiError = JsonConvert.DeserializeObject<ApiException>(errorString);
                    if (string.IsNullOrEmpty(apiError.Detail))
                    {
                        apiError.Detail = apiError.ResponseException?.ExceptionMessage;
                    }
                    throw new Exception(apiError.Detail);
                }

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<IssuerResponse>(jsonString);

                return data;
            }
            catch(Exception ex)
            {
                throw ex;
            }
        }

        public async Task<IssuerResponse> VerifyLoginOTP(LoginOTPRequest dto)
        {
            try
            {
                string endpoint = "/api/v1/Auth/OTP";
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                var httpResponse = await _httpClient.PostAsync(endpoint, content);

                if (!httpResponse.IsSuccessStatusCode)
                {
                    var errorString = await httpResponse.Content.ReadAsStringAsync();
                    var apiError = JsonConvert.DeserializeObject<ApiException>(errorString);
                    if (string.IsNullOrEmpty(apiError.Detail))
                    {
                        apiError.Detail = apiError.ResponseException?.ExceptionMessage;
                    }
                    throw new Exception(apiError.Detail);
                }

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<IssuerResponse>(jsonString);

                return data;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<IssuerResponse> VerifyRegisterOTP(RegisterOTPRequest dto)
        {
            try
            {
                string endpoint = "/api/v1/Register/OTP";
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                var httpResponse = await _httpClient.PostAsync(endpoint, content);

                if (!httpResponse.IsSuccessStatusCode)
                {
                    var errorString = await httpResponse.Content.ReadAsStringAsync();
                    var apiError = JsonConvert.DeserializeObject<ApiException>(errorString);
                    if (string.IsNullOrEmpty(apiError.Detail))
                    {
                        apiError.Detail = apiError.ResponseException?.ExceptionMessage;
                    }
                    throw new Exception(apiError.Detail);
                }

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<IssuerResponse>(jsonString);

                return data;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<IssuerRegisterResponse> RegisterPhone(RegisterBlueNumberRequest dto)
        {
            try
            {
                string endpoint = "/api/v1/Register";
                var content = new StringContent(JsonConvert.SerializeObject(dto), Encoding.UTF8, HttpContentMediaTypes.JSON);
                var httpResponse = await _httpClient.PostAsync(endpoint, content);

                if (!httpResponse.IsSuccessStatusCode)
                {
                    var errorString = await httpResponse.Content.ReadAsStringAsync();
                    var apiError = JsonConvert.DeserializeObject<ApiException>(errorString);
                    if (string.IsNullOrEmpty(apiError.Detail))
                    {
                        apiError.Detail = apiError.ResponseException?.ExceptionMessage;
                    }
                    throw new Exception(apiError.Detail);
                }

                var jsonString = await httpResponse.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<IssuerRegisterResponse>(jsonString);

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