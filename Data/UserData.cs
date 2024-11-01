using System;
using SampleSecureWeb.Models;

namespace SampleSecureWeb.Data;

public class UserData : IUser
{
    private readonly ApplicationDbContext _db;
    public UserData(ApplicationDbContext db)
    {
        _db = db;
    }

    public User GetUserByUsername(string username)
    {
        throw new NotImplementedException();
    }

    public User Login(User user)
    {
        var _user = _db.Users.FirstOrDefault(u => u.Username == user.Username);
        if (_user == null)
        {
            throw new Exception("Username not found");
        }
        if (!BCrypt.Net.BCrypt.Verify(user.Password, _user.Password))
        {
            throw new Exception("Password is incorrect");
        }
        return _user;
    }

    public User Registration(User user)
    {
        try
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            _db.Users.Add(user);
            _db.SaveChanges();
            return user;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public void UpdatePassword(User user)
    {
        throw new NotImplementedException();
    }
}
