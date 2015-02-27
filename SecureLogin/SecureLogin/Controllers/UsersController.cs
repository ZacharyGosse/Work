using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using SecureLogin.Models;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;
using System.Threading.Tasks;
using System.Web.Helpers;
using System.IO;
using System.Text.RegularExpressions;
using SimpleCrypto;
using System.Windows.Media.Imaging;

namespace SecureLogin.Controllers
{
    public class UsersController : Controller
    {
        
        private UserDBContext db = new UserDBContext();
        private LogDbContext logdb = new LogDbContext();
        //Controller Private Methods//
        private void genLog(string action, string message, string username)
        {
            Log log = new Log();
            log.action = action;
            log.username = username;
            log.message = message;
            log.timestamp = DateTime.Now;

            logdb.Logs.Add(log);
            logdb.SaveChanges();
        }
        

        // GET: Users
        public ActionResult Index()
        {
            return View(db.Users.ToList());
        }

        // GET: Users/Profile/5
        public ActionResult Profile()
        {
            
            if (!Request.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            User user = db.Users.Find(this.User.Identity.Name);
            if (user == null)
            {
                return HttpNotFound();
            }
            UserPassChange upc = uToUpc(user);
            
            return View(upc);
        }

        private UserPassChange uToUpc(User user){
            UserPassChange upc = new UserPassChange();
            upc.username = user.username;
            upc.avPath = user.avPath;
            upc.thumbPath = user.thumbPath;
            upc.email = user.email;

            return (upc);  
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Profile([Bind(Include = "Image,email,username")] UserPassChange user)
        {
            user.username = this.User.Identity.Name;
            User ruser = db.Users.Find(user.username);
            user.avPath = ruser.avPath;
            user.thumbPath = ruser.thumbPath;
            user.email = ruser.email;
            var validImageTypes = new string[]
            {
             "image/gif",
              "image/jpeg",
               "image/bmp",
                "image/png"
            };
            //BitmapEncoder be = BitmapEncoder.Create(System.Guid);
            if (user.Image == null || user.Image.ContentLength == 0)
            {

            }
            else if (user.Image.ContentLength > 1000000)
            {
                ModelState.AddModelError("ImageUpload", "Image cannot be larger than 1mb");
            }
            else if (!validImageTypes.Contains(user.Image.ContentType))
            {
                ModelState.AddModelError("ImageUpload", "Please choose either a GIF, JPG or PNG image.");

            }

            else
            {

                WebImage photo;
                String newFileName = "";
                var imagePath = "";
                var imageThumbPath = "";



                photo = new System.Web.Helpers.WebImage(user.Image.InputStream);



                imagePath = "/Content/images/";
                newFileName = Guid.NewGuid().ToString() + "_." + photo.ImageFormat;


                photo.Save(@"~\" + imagePath + newFileName);

                imageThumbPath = "/Content/images/thumbs/";
                photo.Resize(width: 100, height: 100, preserveAspectRatio: true, preventEnlarge: true);
                photo.Save(@"~\" + imageThumbPath + newFileName);

                ruser.avPath = imagePath + newFileName;
                ruser.thumbPath = imageThumbPath + newFileName;
                user.avPath = ruser.avPath;
                user.thumbPath = ruser.thumbPath;
                user.email = ruser.email;
                db.Entry(ruser).State = EntityState.Modified;
                db.SaveChanges();

                genLog("Profile", "Update Profile", user.username);

            }
            return View(user);
        
        }
        public ActionResult Error()
        {
            return View();
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more Profile see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(true)]
        public ActionResult Create([Bind(Include = "username,email,newpass,confpass")] RegisterUser regU)
        {
            if (ModelState.IsValid)
            {
            
               
                var crypto = new SimpleCrypto.PBKDF2();
                regU.newpass = crypto.Compute(regU.newpass);
                

                User user = new User();
                user.username = regU.username;
                user.password = regU.newpass;
                user.salt = crypto.Salt;
                user.email = regU.email;
                user.activated = false;
                string actKey = "/Activ?kstr=" + RandomPassword.Generate(44, PasswordGroup.Uppercase, PasswordGroup.Lowercase, PasswordGroup.Numeric);
                user.actString = actKey;
                regU = null;
                db.Users.Add(user);
                db.SaveChanges();
                Session["smsg"] = "User Created, You will recieve a verification email";
                genLog("Create", "User Created: Verify Link = " + actKey, user.username);
                return RedirectToAction("Success");
            }

            return View(regU);
        }

        // GET: Users/Edit/5
        public ActionResult Edit()
        {
            
            if (!Request.IsAuthenticated)
            {   
               return RedirectToAction("Login");
            }
            string name = this.User.Identity.Name;

            User user = db.Users.Find(name);
            UserPassChange upc = new UserPassChange();
            upc.email = user.email;
            upc.username = user.username;
            
            user.password = "";
           
            return View(upc);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(true)]
        public ActionResult Edit([Bind(Include = "email,password,newpass,confpass")] UserPassChange upc)
        {
            
                var crypto = new SimpleCrypto.PBKDF2();
                
                upc.username = this.User.Identity.Name;
                User user = db.Users.Find(upc.username);
                upc.password = crypto.Compute(upc.password,user.salt);
                if (upc.password == user.password) {
                    user.password = crypto.Compute(upc.newpass);
                    user.salt = crypto.Salt;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    Session["smsg"] = "Password Updated.";
                    genLog("PassChange", "Password Updated", user.username);
                    return RedirectToAction("Success");
                }

                ModelState.AddModelError("password", "Wrong Password");
                upc.password = "";
            return View(upc);
        }

    

        [HttpGet]
        public ActionResult Login()
        {
            if (Request.IsAuthenticated)
            {
                return RedirectToAction("Index");
            }
            return View();
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more Profile see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login([Bind(Include = "username,password")] User user,bool rememberMe)
        {
            if (ModelState.IsValid)
            {
                if (IsValid(user.username, user.password))
                {
                    user = db.Users.Find(user.username);
                    FormsAuthentication.SetAuthCookie(user.username, rememberMe);
                    user.attempts = 0;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    genLog("Login", "Logged in", user.username);
                    return RedirectToAction("Profile", "Users");
                }
                user = db.Users.Find(user.username);
                if (user.locked == true) { 
                    ModelState.AddModelError("LoginMsg", "Account Locked. Follow link in email to unlock");
                   
                }
                else
                {
                    user.attempts++;
                    if (user.attempts == 5)
                    {
                        user.locked = true;
                        string unlKey = "/Unlock?kstr=" + RandomPassword.Generate(44, PasswordGroup.Uppercase, PasswordGroup.Lowercase, PasswordGroup.Numeric);
                        genLog("Login", "Accout Locking, link = " + unlKey, user.username);
                        user.unlString = unlKey;
                        ModelState.AddModelError("LoginMsg", "This Account is locked, follow link in email to unlock");
                        db.Entry(user).State = EntityState.Modified;
                        db.SaveChanges();
                        
                    }
                    else
                    {
                        ModelState.AddModelError("LoginMsg", "Login Data is Incorrect. " + (5 - user.attempts) + " Attempts remaining");
                        db.Entry(user).State = EntityState.Modified;
                        db.SaveChanges();
                    }
                }
            }
            user.password = "";
            return View(user);
        }

        public ActionResult Reset(string kstr)
        {
            if (kstr != null && kstr.Length > 0 && kstr.Length < 45)
            {
                kstr = Regex.Replace(kstr, "[^0-9a-zA-Z]+", "");
                User user = db.Users.FirstOrDefault(User => User.forString == "/Reset?kstr="+kstr);

                UserPassChange upc = uToUpc(user);
                if (user != null)
                {

                    return View(upc);
                }
            }
            return RedirectToAction("Index");
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Reset([Bind(Include = "username,newpass,confpass")] UserPassChange upc)
        {

            var crypto = new SimpleCrypto.PBKDF2();
            
            //username = ViewBag.username;
            //upc.username = this.User.Identity.Name;
            User user = db.Users.Find(upc.username) ;
            upc.password = crypto.Compute(upc.newpass);
            user.password = upc.password;
            user.forString = "";
                user.salt = crypto.Salt;
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                genLog("Reset","Password Reset", user.username);
                Session["smsg"] = "Your password has been reset.";
                //ModelState.AddModelError("LoginMsg", "Password Successfuly Changed!");
                return RedirectToAction("Success");
        }
        public ActionResult Unlock(string kstr)
        {
            if (kstr != null && kstr.Length > 0 && kstr.Length < 45)
            {
                kstr = Regex.Replace(kstr, "[^0-9a-zA-Z]+", "");
                User user = db.Users.FirstOrDefault(User => User.unlString == "/Unlock?kstr="+kstr);
               
                UserPassChange upc = uToUpc(user);
                if (user != null)
                {
                    user.locked = false;
                    user.attempts = 0;
                    user.unlString = null;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    genLog("Unlock", "Accout Unlocking", user.username);
                    Session["smsg"] = "Your account has been unlocked.";
                    return RedirectToAction("Success");
                }
            }
            return RedirectToAction("Index");
        }

        public ActionResult Forgot()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(true)]
        public ActionResult Forgot([Bind(Include = "username,email")] UserPassChange upc)
        {

            User user = db.Users.Find(upc.username);
            if (user == null)
            {

            }
            else if (user.email != upc.email) 
            { 
                user = null; 
            }
            
            if (user != null)
            {
                String forKey = "/Reset?kstr=" + RandomPassword.Generate(44, PasswordGroup.Uppercase, PasswordGroup.Lowercase, PasswordGroup.Numeric);
                user.forString = forKey;
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                genLog("Forgot", "Accout Reset Sent: link = "+forKey, user.username);
                  return RedirectToAction("Index", "Users");
             }
             else
                {
                    ModelState.AddModelError("Error", "User or Email not found");
                }

            return View(upc);
        }

        private bool IsValid(string username, string password)
        {
            var crypto = new SimpleCrypto.PBKDF2();
            bool isValid = false;

            User user = db.Users.Find(username);

            if (user != null)
            {
                if (user.password == crypto.Compute(password, user.salt))
                {
                    isValid = true;
                }
            }
            return isValid;
        }



        public ActionResult SignOut()
        {
            genLog("SignOut", "Logged Off", this.User.Identity.Name);
            FormsAuthentication.SignOut();

            return RedirectToAction("LogOut");
        }

        public ActionResult LogOut()
        {


            return View();
        }


        public ActionResult Activ(string kstr)
        {
            if (kstr != null && kstr.Length > 0 && kstr.Length < 45)
            {
                kstr = Regex.Replace(kstr, "[^0-9a-zA-Z]+", "");
                User user = db.Users.FirstOrDefault(User => User.actString == "/Activ?kstr=" + kstr);

                if (user != null)
                {

                    user.actString = null;
                    user.activated = true;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    genLog("Activ", "Accout Verified", user.username);
                    Session["smsg"] = "Your account has been activated.";
                    //ModelState.AddModelError("LoginMsg", "Password Successfuly Changed!");
                    return RedirectToAction("Success");
                    
                }
            }
            return RedirectToAction("Index");
        }

        public ActionResult Success()
        {
            if (Session["smsg"] == null)
            {
                RedirectToAction("Index");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Success(string topost)
        {
            //Session.Abandon();
            return RedirectToAction("Login");
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }



    }

}
