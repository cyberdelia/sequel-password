require 'bundler'
Bundler.require

require 'simplecov'
SimpleCov.start do
  add_filter('spec/')
end

require 'sequel'
require 'sequel_password'

RSpec.configure do |config|
  config.order = 'random'

  config.before(:suite) do
    db = Sequel.connect('sqlite:/')

    db.create_table(:default) do
      primary_key :id
      varchar     :password
    end

    class DefaultUser < Sequel::Model(:default)
      plugin :password
    end

    class BCryptUser < Sequel::Model(:default)
      plugin :password, hashers: {
        bcrypt: Sequel::Plugins::Password::BCryptHasher.new
      }
    end

    class BCryptSHA256User < Sequel::Model(:default)
      plugin :password, hashers: {
        bcrypt: Sequel::Plugins::Password::BCryptSHA256Hasher.new
      }
    end

    db.create_table(:custom) do
      primary_key :id
      varchar     :password_digest
    end

    class AlternateColumnUser < Sequel::Model(:custom)
      plugin :password, column: :digest
    end
  end

  config.around do |example|
    Sequel::Model.db.transaction(rollback: :always) { example.run }
  end
end
