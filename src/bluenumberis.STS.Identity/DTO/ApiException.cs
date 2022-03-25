namespace BlueNumber.Issuer.Api.DTO
{
    public class ApiException
    {
        public string Message { get; set; }
        public bool IsError { get; set; }
        public string Detail { get; set; }
        public ResponseException ResponseException { get; set; }
    }

    public class ResponseException
    {
        public string ExceptionMessage { get; set; }
    }
}
