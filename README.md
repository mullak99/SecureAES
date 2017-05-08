# SecureAES
A C# library used to encrypt files with AES-256.


//TODO - Complete this section.

# Download
The Latest Releases can always be found at either:

http://github.com/mullak99/SecureAES/releases/latest

http://builds.mullak99.co.uk/SecureAES/latest

# Usage

- Add the library as a referance to your project
- Create an instance of the library within your code


//TODO - Complete this section.

# Example Code

SecureAES aes = new SecureAES();

aes.AES_Encrypt(inputFile, password);


//TODO - Complete this section.

# Changelog

|---| 1.0.0.0 |---|

- Initial Release

|---| 1.0.1.0 |---|

- Checks final checksum with the embedded checksum of the original file to ensure that the password was correct
