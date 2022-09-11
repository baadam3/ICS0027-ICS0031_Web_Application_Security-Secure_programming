using Microsoft.AspNetCore.Identity;

namespace Domain
{
    public class DiffieHellmanPoco
    {
        public int Id { get; set; }

        public ulong SharedPrime { get; set; }
        
        public ulong SharedBase { get; set; }
        
        public ulong SecretA { get; set; }
        
        public ulong SecretB { get; set; }

        public ulong SharedSecret { get; set; }
        
        public string UserId { get; set; }
        public IdentityUser User { get; set; }
    }
}