require "bundler"
Bundler.require

require "simplecov"
SimpleCov.start do
  add_filter('spec/')
end

require "sequel"
require "sequel_password"

RSpec.configure do |config|
  config.order = 'random'

  config.before(:suite) do
    Sequel::Model.plugin(:schema)
    Sequel.connect('sqlite:/')

    class DefaultUser < Sequel::Model
      set_schema do
        primary_key :id
        varchar     :digest
      end

      plugin :password
    end

    class BCryptUser < Sequel::Model
      set_schema do
        primary_key :id
        varchar     :digest
      end

      plugin :password, hashers: { bcrypt: Sequel::Plugins::Password::BCryptHasher.new }
    end

    class BCryptSHA256User < Sequel::Model
      set_schema do
        primary_key :id
        varchar     :digest
      end

      plugin :password, hashers: { bcrypt: Sequel::Plugins::Password::BCryptSHA256Hasher.new }
    end

    class AlternateColumnUser < Sequel::Model
      set_schema do
        primary_key :id
        varchar     :password_digest
      end

      plugin :password, column: :digest
    end

    DefaultUser.create_table!
    BCryptUser.create_table!
    BCryptSHA256User.create_table!
    AlternateColumnUser.create_table!
  end

  config.around(:each) do |example|
    Sequel::Model.db.transaction(rollback: :always) { example.run }
  end
end
