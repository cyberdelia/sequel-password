require 'base64'
require 'bcrypt'
require 'openssl'
require 'pbkdf2'
require 'securerandom'

module Sequel
  module Plugins
    module Password
      # @!attribute [r] algorithm
      #   @return [Symbol] name of the alogorithm implemented by the hasher
      # @abstract Subclass or override this class to implements a custom
      #   Hasher.
      class Hasher
        attr_reader :algorithm

        # Returns salt value to be used for hashing.
        #
        # @return [String] random salt value.
        def salt
          # 72 bits
          SecureRandom.hex(9)
        end

        # Returns if the given password match the encoded password.
        #
        # @param [String] password in plain text
        # @param [String] encoded password to be matched
        # @return [Boolean] if password match encoded password.
        def verify(_password, _encoded)
          raise NotImplementedError
        end

        # Returns given password encoded with the given salt.
        #
        # @param [String] password in plain text
        # @param [String] salt to be used during hashing
        # @return [String] given password hashed using the given salt
        def encode(_password, _salt)
          raise NotImplementedError
        end

        # Returns if given encoded password needs to be updated.
        #
        # @param [String] encoded password
        # @return [Boolean] if encoded password needs to be updated
        def must_update(_encoded)
          false
        end

        private

        def constant_time_compare(a, b)
          check = a.bytesize ^ b.bytesize
          a.bytes.zip(b.bytes) { |x, y| check |= x ^ y }
          check.zero?
        end
      end

      # PBKDF2Hasher implements a PBKDF2 password hasher using 24000 iterations
      # by default.
      class PBKDF2Hasher < Hasher
        def initialize
          @algorithm = :pbkdf2_sha256
          @iterations = 24_000
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
          _, iterations, salt, = encoded.split('$', 4)
          hash = encode(password, salt, iterations.to_i)
          constant_time_compare(encoded, hash)
        end

        def must_update(encoded)
          _, iterations, = encoded.split('$', 4)
          iterations.to_i != @iterations
        end
      end

      # BCryptSHA256Hasher implements a BCrypt password hasher using SHA256.
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

      # BCryptHasher implements a BCrypt password hasher.
      class BCryptHasher < BCryptSHA256Hasher
        def initialize
          @algorithm = :bcrypt
          @cost = 12
          @digest = nil
        end
      end

      # SHA1Hasher implements a SHA1 password hasher.
      #
      # @deprecated This hasher is present only for backward compatibility.
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
          _, salt, = encoded.split('$', 3)
          hash = encode(password, salt)
          constant_time_compare(encoded, hash)
        end
      end
    end
  end
end
