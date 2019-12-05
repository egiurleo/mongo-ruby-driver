require 'mongo'
require 'support/lite_constraints'

RSpec.configure do |config|
  config.extend(LiteConstraints)
end

describe Mongo::Crypt::EncryptionContext do
  require_libmongocrypt

  let(:context) { described_class.new(mongocrypt, io, db_name, cmd, options) }

  let(:mongocrypt) { Mongo::Crypt::Binding.mongocrypt_new }
  let(:io) { double("Mongo::ClientEncryption::IO") }
  let(:db_name) { 'admin' }
  let(:cmd) do
    {
      "find": "test",
      "filter": {
          "ssn": "457-55-5462"
      }
    }
  end

  let(:options) { {} }

  before do
    Mongo::Crypt::Binding.mongocrypt_init(mongocrypt)
  end

  after do
    Mongo::Crypt::Binding.mongocrypt_destroy(mongocrypt)
  end

  describe '#initialize' do
    it 'does something?' do
      context
    end
  end
end