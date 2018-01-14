require 'spec_helper'

describe Sequel::Plugins::Password do
  subject(:user) { DefaultUser.new }

  it 'has an inherited instance variable @column' do
    expect(DefaultUser.inherited_instance_variables).to include(:@column)
  end

  it 'has an inherited instance variable @hashers' do
    expect(DefaultUser.inherited_instance_variables).to include(:@hashers)
  end

  describe 'set_unusable_password' do
    let(:secret) { 'lètmein' }

    before { user.password = secret }

    it 'sets an unusable password' do
      expect { user.set_unusable_password }.to change(user, :password)
      expect(user.password).to match(/^!/)
      expect(user.password.length).to eq(41)
    end
  end

  describe '#authenticate' do
    let(:secret) { 'lètmein' }

    before { user.password = secret }

    it 'returns true if authentication is successful' do
      expect(user.authenticate(secret)).to be_truthy
    end

    it 'returns false when authentication fails' do
      expect(user.authenticate('')).to be_falsey
    end
  end

  describe Sequel::Plugins::Password::PBKDF2Hasher do
    let(:hasher) { described_class.new }
    let(:password) { 'lètmein' }
    let(:salt) { 'seasalt' }

    it 'encodes the password properly' do
      encoded = hasher.encode(password, salt)
      expect(encoded).to eq("pbkdf2_sha256$24000$#{salt}$V9DfCAVoweeLwxC/L2mb+7swhzF0XYdyQMqmusZqiTc=")
      expect(hasher.verify(password, encoded)).to be_truthy
      expect(hasher.verify(password.reverse, encoded)).to be_falsey
    end

    it 'allows blank password' do
      blank_encoded = hasher.encode('', salt)
      expect(blank_encoded).to match(/^pbkdf2_sha256\$/)
      expect(hasher.verify('', blank_encoded)).to be_truthy
      expect(hasher.verify(' ', blank_encoded)).to be_falsey
    end
  end

  describe Sequel::Plugins::Password::BCryptSHA256Hasher do
    let(:hasher) { described_class.new }
    let(:password) { 'lètmein' }

    it 'encodes the password properly' do
      encoded = hasher.encode(password, hasher.salt)
      expect(encoded).to match(/^bcrypt_sha256\$/)
      expect(hasher.verify(password, encoded)).to be_truthy
      expect(hasher.verify(password.reverse, encoded)).to be_falsey
    end
  end

  describe Sequel::Plugins::Password::BCryptHasher do
    let(:hasher) { described_class.new }
    let(:password) { 'lètmein' }

    it 'encodes the password properly' do
      encoded = hasher.encode(password, hasher.salt)
      expect(encoded).to match(/^bcrypt\$/)
      expect(hasher.verify(password, encoded)).to be_truthy
      expect(hasher.verify(password.reverse, encoded)).to be_falsey
    end
  end

  describe Sequel::Plugins::Password::SHA1Hasher do
    let(:hasher) { described_class.new }
    let(:password) { 'lètmein' }
    let(:salt) { 'seasalt' }

    it 'encodes the password properly' do
      encoded = hasher.encode(password, salt)
      expect(encoded).to eq("sha1$#{salt}$cff36ea83f5706ce9aa7454e63e431fc726b2dc8")
      expect(hasher.verify(password, encoded)).to be_truthy
      expect(hasher.verify(password.reverse, encoded)).to be_falsey
    end

    it 'allows blank password' do
      blank_encoded = hasher.encode('', salt)
      expect(blank_encoded).to match(/^sha1\$/)
      expect(hasher.verify('', blank_encoded)).to be_truthy
      expect(hasher.verify(' ', blank_encoded)).to be_falsey
    end
  end
end
