namespace FDS.Models
{
    public class Response
    {
        public Object? Data { get; set; } = null;
        public bool Success { get; set; }
        public string? Status { get; set; }
        public string? Message { get; set; }
    }
}
