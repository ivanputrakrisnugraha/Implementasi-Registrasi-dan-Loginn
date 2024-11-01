using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SampleSecureWeb.Data;
using SampleSecureWeb.Models;
using SampleSecureWeb.ViewModel;

namespace SampleSecureWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;
        public AccountController(IUser user)
        {
            _userData = user;
        }

        // GET: AccountController
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    if (!IsValidPassword(registrationViewModel.Password))
                    {
                        ModelState.AddModelError("Password", "- Min character 12.-Harus mengandung huruf besar, huruf kecil, dan angka");
                        return View(registrationViewModel); // Tetap di halaman registrasi jika validasi gagal
                    }
                    var user = new Models.User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        RoleName = "contributor"
                    };
                    _userData.Registration(user);
                    return RedirectToAction("Index", "Home");
                }
                return View(registrationViewModel);
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;

            }
            return View(registrationViewModel);
        }
         private bool IsValidPassword(string password)
        {
            if (password.Length < 12) return false;
            if (!password.Any(char.IsUpper)) return false;
            if (!password.Any(char.IsLower)) return false;
            if (!password.Any(char.IsDigit)) return false;
            return true;
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                // loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");

                var user = new User
                {
                    Username = loginViewModel.Username,
                    Password = loginViewModel.Password
                };

                var loginUser = _userData.Login(user);
                if (loginUser == null)
                {
                    ViewBag.Message = "Invalid login attempt.";
                    return View(loginViewModel);
                }

                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim(ClaimTypes.Role, loginUser.RoleName)
                    };
                var identity = new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = loginViewModel.RememberLogin
                    });
                return RedirectToAction("Index", "Home");


            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }
            return View(loginViewModel);
        }
        public async Task<ActionResult> Logout ()
        {
            await HttpContext.SignOutAsync (CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home"); 
        }
        public ActionResult ChangePassword()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ChangePassword(ChangePwViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = _userData.GetUserByUsername(model.Username);
            if (user == null)
            {
                ModelState.AddModelError("", "User not found");
                return View(model);
            }

            // Verify old password
            if (!BCrypt.Net.BCrypt.Verify(model.OldPassword, user.Password))
            {
                ModelState.AddModelError("", "Old password is incorrect");
                return View(model);
            }

            // Update password
            user.Password = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
            _userData.UpdatePassword(user);

            ViewBag.Message = "Password changed successfully. Please login again.";
            ViewBag.ShowLoginButton = true; // Tampilkan tombol login setelah password berhasil diubah

            return View();
        }
    }
}