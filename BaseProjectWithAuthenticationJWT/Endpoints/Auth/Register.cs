using BaseProjectWithAuthenticationJWT.Models.Entities;
using BaseProjectWithAuthenticationJWT.Models;
using FluentValidation;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BaseProjectWithAuthenticationJWT.Endpoints.Auth
{
    public static class Register
    {
        public static async Task<IResult> HandlerAsync([FromBody] RegisterRequest req, AppDbContext context, IValidator<RegisterRequest> validator, IPasswordHasher<Users> hasher)
        {
            var validation = await validator.ValidateAsync(req);

            if (!validation.IsValid)
            {
                return Results.ValidationProblem(validation.ToDictionary());
            }

            if (await context.Users.AnyAsync(x => x.Username == req.Username))
            {
                return Results.BadRequest("Este usuário já está cadastrado.");
            }

            var user = new Users
            {
                Username = req.Username,
                Name = req.Name,
                Role = "common"
            };

            user.Password = hasher.HashPassword(user, req.ConfirmPassword);

            context.Users.Add(user);

            await context.SaveChangesAsync();

            return Results.Ok();
        }
    }

    public class RegisterValidation : AbstractValidator<RegisterRequest>
    {
        public RegisterValidation()
        {
            RuleFor(request => request.Username)
                .NotEmpty()
                    .WithMessage("O campo Username é obrigatório.");

            RuleFor(request => request.Name)
                .NotEmpty()
                    .WithMessage("O campo Name é obrigatório.");

            RuleFor(request => request.Password)
                .NotEmpty()
                .WithMessage("O campo Password é obrigatório.");

            RuleFor(request => request.ConfirmPassword)
                .NotEmpty().WithMessage("O campo ConfirmPassword é obrigatório.")
                .Equal(request => request.Password)
                .WithMessage("A senha e a confirmação de senha devem ser iguais.");
        }
    }

    public record RegisterRequest(string Name, string Username, string Password, string ConfirmPassword);
}
