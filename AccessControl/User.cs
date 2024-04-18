using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Security.Cryptography;
using System.IO;


namespace AccessControl
{
    public class User
    {
        public string UserName { get; set; }
        public string Password_PlainText { get; set; }
        public string Password_Hash { get; set; }
        public string Password_SaltedHash { get; set; }
        public string Password_SaltedHashSlow { get; set; }
        public string Salt { get; set; }


        public User (string _UserName, string _Password)
        {
            UserName = _UserName;
            Password_PlainText = _Password;
        }

        public User ()
        {

        }

        public void AddUser()
        {
            //Apliquem hash
            using(SHA256 sHA256 = SHA256.Create()){
                byte[] hashValue = sHA256.ComputeHash(Encoding.UTF8.GetBytes(this.Password_PlainText));
                this.Password_Hash = BytesToStringHex(hashValue);
            }

            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Generate a random salt
                byte[] salt = new byte[32]; // 32 bytes = 256 bits, a good size for a salt
                rngCsp.GetBytes(salt);

               

                // Store the salt
                this.Salt = Encoding.UTF8.GetString(salt);
            }


            using (SHA256 sHA256 = SHA256.Create())
            {
                byte[] hashValue = sHA256.ComputeHash(Encoding.UTF8.GetBytes(this.Password_PlainText+this.Salt));
                this.Password_SaltedHash = BytesToStringHex(hashValue);
            }
            //Apliquem hash+salt
            //this.Salt=
            //this.Password_SaltedHash=

            //Apliquem hash+salt amb algorisme de hash lent.
            //this.Password_SaltedHashSlow=
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(this.Password_Hash, Encoding.UTF8.GetBytes(this.Salt), 10000))
            {
                byte[] slowHashValue = pbkdf2.GetBytes(32); // 32 bytes = 256 bits, the same size as SHA256
                this.Password_SaltedHashSlow = this.BytesToStringHex(slowHashValue);
            }

            ((App)Application.Current).Database.Add(this);            
        }



        public bool Validate(string _UserName, string _Password)
        {
            // Find the user by username
            User MyUser = ((App)Application.Current).Database.Find(user => user.UserName == _UserName);

            // If the user is found
            if (!ReferenceEquals(MyUser, null))
            {
                //// Validate with plain text
                //if (MyUser.Password_PlainText.Equals(_Password))
                //{
                ////    return true; // Password is valid
                //}

                // Validate with hash (comment out the previous validation)
                
                //if (MyUser.Password_Hash.Equals(ComputeHash(_Password)))
                //{
                //    return true; // Password is valid
                //}
                

                // Validate with hash and salt (comment out the previous validation)
                
                //if (MyUser.Password_SaltedHash.Equals(ComputeHashWithSalt(_Password, MyUser.Salt)))
                //{
                //    return true; // Password is valid
                //}
                

                // Validate with slow hash and salt
                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(_Password, Encoding.UTF8.GetBytes(MyUser.Salt), 10000))
                {
                    byte[] slowHashValue = pbkdf2.GetBytes(32); // 32 bytes = 256 bits, the same size as SHA256
                    string slowHash = BytesToStringHex(slowHashValue);

                    // Compare the slow hash with the stored slow hash
                    if (MyUser.Password_SaltedHashSlow.Equals(slowHash))
                    {
                        return true; // Password is valid
                    }
                }
            }
            return false; // User not found or password invalid
        }

        // Helper method to compute hash
        private string ComputeHash(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashValue = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BytesToStringHex(hashValue);
            }
        }

        // Helper method to compute hash with salt
        private string ComputeHashWithSalt(string password, string salt)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashValue = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + salt));
                return BytesToStringHex(hashValue);
            }
        }


        string BytesToStringHex (byte[] result)
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte b in result)
                stringBuilder.AppendFormat("{0:x2}", b);

            return stringBuilder.ToString();
        }
    }

}
