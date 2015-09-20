# Sequel password

This sequel plugin adds authentication and password hashing to Sequel models.
It supports pbkdf2 and bcrypt hashers.

## Installation

Install it directly using gem:

```
gem install sequel_password
```

Or adding it to your ``Gemfile``:

```
gem "sequel_password"
```

##  Usage

### Configure

A straightforward example, using the password column for storage explicitely,
and using the default hashers:

```ruby
class User < Sequel::Model
  plugin :password, column: :password
end
```

You can also specify a custom list of hashers to be used. The first hashers will
be considered as the default, choose carefully:

```ruby
class User < Sequel::Model
  plugin :password, hashers: {
    pbkdf2_sha256: PBKDF2Hasher.new,
    bcrypt_sha256: BCryptSHA256Hasher.new
  }
end
```

### Authenticate

To authenticate users with their given plain text password:

```ruby
user = User[email: email]
user && user.authenticate(password)
```
