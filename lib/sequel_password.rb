require "base64"
require "bcrypt"
require "openssl"
require "pbkdf2"
require "securerandom"

module Sequel
  module Plugins
    module Password
      class InvalidHasherException < Exception; end

      def self.configure(model, options = {})
        model.instance_eval do
          @column = options.fetch(:column, :digest)
          @hashers = options.fetch(:hashers,
            pbkdf2_sha256: PBKDF2Hasher.new,
            bcrypt_sha256: BCryptSHA256Hasher.new,
            bcrypt: BCryptHasher.new,
            sha1: SHA1Hasher.new)
        end
      end

      module ClassMethods
        attr_reader :column, :hashers

        Plugins.inherited_instance_variables(self,
          "@column": :digest, "@hashers": {})

        def make_password(password, salt: nil, algorithm: :default)
          return "!#{SecureRandom.hex(20)}" if password.nil?

          salt = hasher(algorithm).salt if salt.nil?
          hasher(algorithm).encode(password, salt)
        end

        def hasher(algorithm = :default)
          @hashers.fetch(algorithm.to_sym, @hashers.values.first)
        end

        def usable_password?(encoded)
          return false if encoded.nil? || encoded.start_with?("!")

          algorithm = encoded.split('$').first
          !hasher(algorithm).nil?
        end

        def check_password(password, encoded, setter: nil, algorithm: :default)
          return false if password.nil? || !usable_password?(encoded)

          preferred = hasher(algorithm)
          hasher = hasher(encoded.split('$').first)

          must_update = hasher.algorithm != preferred.algorithm
          must_update = preferred.must_update(encoded) unless must_update

          correct = hasher.verify(password, encoded)
          setter.call(password) if !setter.nil? && correct && must_update

          correct
        end
      end

      module InstanceMethods
        def authenticate(password)
          encoded = send(model.column)
          model.check_password(password, encoded, setter: method(:"password="))
        end

        def password=(password)
          send("#{model.column}=", model.make_password(password))
        end

        def set_unusable_password
          send("#{model.column}=", model.make_password(nil))
        end
      end

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
          algorithm, iterations, salt, hash = encoded.split('$', 4)
          hash = encode(password, salt, iterations.to_i)
          constant_time_compare(encoded, hash)
        end

        def must_update(encoded)
          algorithm, iterations, salt, hash = encoded.split('$', 4)
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
          algorithm, data = encoded.split('$', 2)
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
          algorithm, salt, hash = encoded.split('$', 3)
          hash = encode(password, salt)
          constant_time_compare(encoded, hash)
        end
      end
    end
  end
end
