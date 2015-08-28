require "sequel"
require "securerandom"
require "sequel_password/hashers"

module Sequel
  module Plugins
    module Password
      class InvalidHasherException < Exception; end

      def self.configure(model, options = {})
        model.instance_eval do
          @column = options.fetch(:column, :password)
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

        private

        def hasher(algorithm = :default)
          @hashers.fetch(algorithm.to_sym, @hashers.values.first)
        end
      end

      module InstanceMethods
        def authenticate(password)
          encoded = send(model.column)
          model.check_password(password, encoded, setter: method(:"#{model.column}="))
        end

        def []=(attr, plain)
          if attr == model.column
            value = model.make_password(plain)
          end
          super(attr, value || plain)
        end

        def set_unusable_password
          send("#{model.column}=", nil)
        end
      end
    end
  end
end
