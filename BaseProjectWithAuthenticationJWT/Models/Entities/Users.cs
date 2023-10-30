using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace BaseProjectWithAuthenticationJWT.Models.Entities
{
    public partial class Users
    {
        [Key]
        public int IdUser { get; set; }

        [StringLength(100)]
        [Unicode(false)]
        public string Name { get; set; } = null!;

        [StringLength(30)]
        [Unicode(false)]
        public string Username { get; set; } = null!;

        [Unicode(false)]
        public string Password { get; set; } = null!;

        [StringLength(25)]
        [Unicode(false)]
        public string Role { get; set; } = null!;

        [Unicode(false)]
        public string? RefreshToken { get; set; }

        [Column(TypeName = "datetime")]
        public DateTime? DtExpirationToken { get; set; }


    }
}
