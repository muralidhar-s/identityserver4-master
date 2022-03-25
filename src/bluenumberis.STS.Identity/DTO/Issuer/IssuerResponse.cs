namespace bluenumberis.STS.Identity.DTO.Issuer
{
    public class IssuerResponse
    {
        public string Message { get; set; }
        public ResultResponse Result { get; set; }
    }

    public class IssuerRegisterResponse
    {
        public string Message { get; set; }
        public bool IsError { get; set; }
        public PersonResponse Result { get; set; }
    }

    public class ResultResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ReferenceId { get; set; }
        public PersonResponse Data { get; set; }
    }

    public class PersonResponse
    {
        public string BlueNumber { get; set; }
        public string Name { get; set; }
        public string Contact { get; set; }
        public string Address { get; set; }
        public string Role { get; set; }
        public string Gender { get; set; }
        public decimal Longitude { get; set; }
        public decimal Latitude { get; set; }
    }
}