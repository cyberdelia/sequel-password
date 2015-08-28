# Sequel password

This sequel plugin adds authentication and password hashing to Sequel models.
It supports pbkdf2 and bcrypt hashers.

# Usage

```ruby
class User < Sequel::Model
  plugin :password, column: :password
end
```
