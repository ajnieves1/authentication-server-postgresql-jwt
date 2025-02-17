Authentication server built with Rust.

Supports separate roles such as Admin/User.
Allows storing of user's credentials to backend database, then hashes the user's password to protect their information. Upon login, the hashed password is checked against the inputted password to validate correctness. 
