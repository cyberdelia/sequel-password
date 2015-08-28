require "base64"
require "bcrypt"
require "openssl"
require "pbkdf2"
require "securerandom"

module Sequel
  module Plugins
    module Password
      class Hasher
        attr_reader :algorithm

        def salt
          # 72 bits
          SecureRandom.hex(9)
        end

        def verify(password, encoded)
          raise NotImplementedError
        end

        def encode(password, salt)
          raise NotImplementedError
        end

        def must_update(encoded)
          false
        end

        private

        def constant_time_compare(a, b)
          check = a.bytesize ^ b.bytesize
          a.bytes.zip(b.bytes) { |x, y| check |= x ^ y }
          check == 0
        end
      end

      class PBKDF2Hasher < Hasher
        def initialize
          @algorithm = :pbkdf2_sha256
          @iterations = 24000
          @digest = OpenSSL::Digest::SHA256.new
        end

        def encode(password, salt, iterations = nil)
          iterations = @iterations if iterations.nil?
          hash = PBKDF2.new(password: password, salt: salt,
            iterations: iterations, hash_function: @digest)
          hash = Base64.strict_encode64(hash.value)
          "#{@algorithm}$#{iterations}$#{salt}$#{hash}"
        end

        def verify(password, encoded)
          _, iterations, salt, hash = encoded.split('$', 4)
          hash = encode(password, salt, iterations.to_i)
          constant_time_compare(encoded, hash)
        end

        def must_update(encoded)
          _, iterations, _, _ = encoded.split('$', 4)
          iterations.to_i != @iterations
        end
      end

      class BCryptSHA256Hasher < Hasher
        def initialize
          @algorithm = :bcrypt_sha256
          @cost = 12
          @digest = OpenSSL::Digest::SHA256.new
        end

        def salt
          BCrypt::Engine.generate_salt(@cost)
        end

        def encode(password, salt)
          password = @digest.digest(password) unless @digest.nil?
          hash = BCrypt::Engine.hash_secret(password, salt)
          "#{@algorithm}$#{hash}"
        end

        def verify(password, encoded)
          _, data = encoded.split('$', 2)
          password = @digest.digest(password) unless @digest.nil?
          hash = BCrypt::Engine.hash_secret(password, data)
          constant_time_compare(data, hash)
        end
      end

      class BCryptHasher < BCryptSHA256Hasher
        def initialize
          @algorithm = :bcrypt
          @cost = 12
          @digest = nil
        end
      end

      class SHA1Hasher < Hasher
        def initialize
          @algorithm = :sha1
          @digest = OpenSSL::Digest::SHA1.new
        end

        def encode(password, salt)
          hash = @digest.digest(salt + password).unpack('H*').first
          "#{@algorithm}$#{salt}$#{hash}"
        end

        def verify(password, encoded)
          _, salt, hash = encoded.split('$', 3)
          hash = encode(password, salt)
          constant_time_compare(encoded, hash)
        end
      end
    end
  end
end
