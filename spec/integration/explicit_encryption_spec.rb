require 'spec_helper'
require 'support/shared/crypt_helper'

RSpec.configure do |config|
  config.include(CryptHelper)
end

describe 'Explicit Encryption' do
  require_libmongocrypt

  let(:client) { authorized_client }
  let(:key_vault_namespace) { 'test.keys' }
  let(:data_key_id) { data_key['_id'].data }

  let(:client_encryption) do
    Mongo::ClientEncryption.new(
      client,
      client_encryption_opts
    )
  end

  let(:client_encryption_opts) do
    {
      kms_providers: kms_providers,
      key_vault_namespace: key_vault_namespace
    }
  end

  before do
    client.use(:test)[:keys].drop
  end

  shared_examples_for 'it can create a data key' do
    it 'creates a data key' do
      data_key_id = client_encryption.create_data_key(kms_provider, data_key_opts)
      expect(data_key_id).to be_a_kind_of(String)
      expect(data_key_id.bytesize).to eq(16)

      num_data_keys = authorized_client
        .use(:test)[:keys]
        .find(_id: BSON::Binary.new(data_key_id, :uuid))
        .count

      expect(num_data_keys).to eq(1)
    end
  end

  shared_examples_for 'it can encrypt/decrypt' do
    before do
      authorized_client.use(:test)[:keys].insert_one(data_key)
    end

    it 'encrypts' do
      encrypted = client_encryption.encrypt(
        value,
        {
          key_id: data_key_id,
          algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic',
        }
      )

      expect(encrypted).to be_a_kind_of(BSON::Binary)
      expect(encrypted.type).to eq(:ciphertext)
      expect(encrypted.data).to eq(Base64.decode64(encrypted_value))
    end

    it 'decrypts' do
      encrypted = BSON::Binary.new(Base64.decode64(encrypted_value), :ciphertext)
      decrypted = client_encryption.decrypt(encrypted)

      expect(decrypted).to eq(value)
      expect(decrypted).to be_a_kind_of(value.class)
    end
  end

  shared_context 'with local KMS options' do
    include_context 'with local KMS provider'
    include_context 'with local data key'

    let(:data_key_opts) { {} }
  end

  shared_context 'with AWS KMS options' do
    include_context 'with AWS KMS provider'
    include_context 'with AWS data key'

    let(:data_key_opts) do
      {
        masterkey: aws_masterkey
      }
    end
  end

  describe '#create_data_key' do
    context 'with local KMS options' do
      include_context 'with local KMS options'

      it_behaves_like 'it can create a data key'
    end

    context 'with AWS KMS options' do
      include_context 'with AWS KMS options'

      it_behaves_like 'it can create a data key'
    end
  end

  context 'value is a string' do
    let(:value) { 'Hello, world!' }

    context 'with local KMS options' do
      let(:encrypted_value) do
        "ASzggCwAAAAAAAAAAAAAAAACyK6qLgrn1nau+o1hmrdkQSEzjHd/ga6aUCTZ\nfTEWr6" +
          "tafDUlktGy2wuw24XnK95utrxgg4234s0qoT1BYzxunkqF92gDlEjG\ne8B1qGu0Odo=\n"
      end

      include_context 'with local KMS options'
      it_behaves_like 'it can encrypt/decrypt'
    end

    context 'with AWS KMS options' do
      let(:encrypted_value) do
        "AQFkgAAAAAAAAAAAAAAAAAACzAvOJg5HCW/xDtbyuJIRCw1/rh92jLnjHBAH\n4WCTcNY" +
          "GAHPIJReqJvMHPi7EggcRX/W0vORojlIFH4bPK+Ik/GytSuiXhNWs\nhQeDEz2zCgE=\n"
      end

      include_context 'with AWS KMS options'
      it_behaves_like 'it can encrypt/decrypt'
    end
  end

  context 'value is an integer' do
    let(:value) { 42 }

    context 'with local KMS options' do
      let(:encrypted_value) do
        "ASzggCwAAAAAAAAAAAAAAAAQasep86pKeqYfp60dsO1qeni+VIOxYRVJEe3J\nkkyJg6ME" +
          "D2MaowHh/SktIgcr6pBxOT3eaX98+HTSHalNjC11jw==\n"
      end

      include_context 'with local KMS options'
      it_behaves_like 'it can encrypt/decrypt'
    end

    context 'with AWS KMS options' do
      let(:encrypted_value) do
        "AQFkgAAAAAAAAAAAAAAAAAAQSbwrKQPsO5zQm4IRbZnuR9ryw6PkGIdECom4\n4JOkd1X3" +
          "fpsUG47fRnTtA94Xk/9qNhs8kg3LReomivRTXoYZAw==\n"
      end

      include_context 'with AWS KMS options'
      it_behaves_like 'it can encrypt/decrypt'
    end
  end

  context 'value is an symbol' do
    let(:value) { BSON::Symbol::Raw.new(:hello_world) }

    context 'with local KMS options' do
      let(:encrypted_value) do
        "ASzggCwAAAAAAAAAAAAAAAAOfj0yCmWG+232eFkDW+wbiUF2QzZFpbt0eg+t\ncR+bafOT" +
          "ikWlWdk8Bg+6lfvLRJcLWnVvCFS/VtIPl40QtN2RMZl8w9qqalDx\n7bQgEbxVfIo=\n"
      end

      include_context 'with local KMS options'
      it_behaves_like 'it can encrypt/decrypt'
    end

    context 'with AWS KMS options' do
      let(:encrypted_value) do
        "AQFkgAAAAAAAAAAAAAAAAAAOqwvBWzo59PMJ5T8pR/f6icSsTwRKW/se/Qqh\nByLS6E6Z" +
          "6DipCOAsdBl0AzfNzCYeBHEIAlzt0wwWsk1/ezrxPwl21cN50BYp\nDDv8w1NCEMM=\n"
      end

      include_context 'with AWS KMS options'
      it_behaves_like 'it can encrypt/decrypt'
    end
  end
end
