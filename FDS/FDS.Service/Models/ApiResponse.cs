namespace FDS.Service.Models
{
    public class ApiResponse<T>
    {
        public T? Response { get; set; } 
        public bool IsSuccess { get; set; }
        public int? StatusCode { get; set; }
        public string? Message { get; set; }
    }
}
