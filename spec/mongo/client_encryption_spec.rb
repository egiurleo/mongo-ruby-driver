require 'mongo'
require 'base64'
require 'lite_spec_helper'
require 'support/shared/crypt_helper'

describe Mongo::ClientEncryption do
  require_libmongocrypt

  RSpec.configure do |config|
    config.include(CryptHelper)
  end

  let(:key_vault_db) { 'admin' }
  let(:key_vault_coll) { 'datakeys' }
  let(:key_vault_namespace) { "#{key_vault_db}.#{key_vault_coll}" }

  let(:client) do
    ClientRegistry.instance.new_local_client(
      [SpecConfig.instance.addresses.first]
    )
  end

  shared_context 'local KMS provider' do
    include_context 'with local KMS provider'
    include_context 'with local data key'

    let(:encrypted_value) do
      "ASzggCwAAAAAAAAAAAAAAAACk0TG2WPKVdChK2Oay9QTYNYHvplIMWjXWlnx\nAVC2hUway" +
        "NZmKBSAVgW0D9tnEMdDdxJn+OxqQq3b9MGIJ4pHUwVPSiNqfFTK\nu3OewGtKV9A=\n"
    end
  end

  shared_context 'AWS KMS provider' do
    include_context 'with AWS KMS provider'
    include_context 'with AWS data key'

    let(:encrypted_value) do
      "AQFkgAAAAAAAAAAAAAAAAAACqjx0+rWi18AIVwOm5VBLF1ga9Unvzo8QTAl1\niSa3k9J" +
        "k55S26zEpQS/G//rMy+mN6SMYoQURBLJri86g6M1+V/8Fz4Hxw4nJ\nJDqWRF3B9pY=\n"
    end
  end

  let(:client_encryption) do
    described_class.new(client, {
      key_vault_namespace: key_vault_namespace,
      kms_providers: kms_providers
    })
  end

  describe '#initialize' do
    let(:client) { new_local_client_nmio([SpecConfig.instance.addresses.first]) }

    include_context 'local KMS provider'

    context 'with nil key_vault_namespace' do
      let(:key_vault_namespace) { nil }

      it 'raises an exception' do
        expect do
          client_encryption
        end.to raise_error(ArgumentError, /:key_vault_namespace option cannot be nil/)
      end
    end

    context 'with invalid key_vault_namespace' do
      let(:key_vault_namespace) { 'three.word.namespace' }

      it 'raises an exception' do
        expect do
          client_encryption
        end.to raise_error(ArgumentError, /invalid key vault namespace/)
      end
    end

    context 'with invalid KMS provider information' do
      let(:kms_providers) { { random_key: {} } }

      it 'raises an exception' do
        expect do
          client_encryption
        end.to raise_error(ArgumentError, /kms_providers option must have one of the following keys/)
      end
    end

    context 'with valid local KMS provider' do
      it 'creates a ClientEncryption object' do
        expect do
          client_encryption
        end.not_to raise_error
      end
    end

    context 'with valid AWS KMS provider' do
      include_context 'AWS KMS provider'

      it 'creates a ClientEncryption object' do
        expect do
          client_encryption
        end.not_to raise_error
      end
    end
  end

  describe '#create_data_key' do
    context 'with local KMS provider' do
      include_context 'local KMS provider'

      it 'returns a string' do
        result = client_encryption.create_data_key('local')
        expect(result).to be_a_kind_of(String)

        # make sure that the key actually exists in the DB
        expect(client.use(key_vault_db)[key_vault_coll].find(_id: BSON::Binary.new(result, :uuid)).count).to eq(1)
      end
    end

    context 'with AWS KMS provider' do
      include_context 'AWS KMS provider'

      it 'returns a string' do
        result = client_encryption.create_data_key('aws', { masterkey: aws_masterkey })
        expect(result).to be_a_kind_of(String)

        # make sure that the key actually exists in the DB
        expect(client.use(key_vault_db)[key_vault_coll].find(_id: BSON::Binary.new(result, :uuid)).count).to eq(1)
      end
    end
  end

  shared_context 'encryption/decryption' do
    # Represented in as Base64 for simplicity
    let(:value) { 'Hello world' }

    before do
      key_vault_collection = client.use(key_vault_db)[key_vault_coll]
      key_vault_collection.drop

      key_vault_collection.insert_one(data_key)
    end
  end

  describe '#encrypt' do
    include_context 'encryption/decryption'

    context 'with local KMS provider' do
      include_context 'local KMS provider'

      it 'returns the correct encrypted string' do
        encrypted = client_encryption.encrypt(
          value,
          {
            key_id: data_key['_id'].data,
            algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
          }
        )

        expect(encrypted).to be_a_kind_of(BSON::Binary)
        expect(encrypted.type).to eq(:ciphertext)
        expect(encrypted.data).to eq(Base64.decode64(encrypted_value))
      end
    end

    context 'with AWS KMS provider' do
      include_context 'AWS KMS provider'

      it 'returns the correct encrypted string' do
        encrypted = client_encryption.encrypt(
          value,
          {
            key_id: data_key['_id'].data,
            algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
          }
        )

        expect(encrypted).to be_a_kind_of(BSON::Binary)
        expect(encrypted.type).to eq(:ciphertext)
        expect(encrypted.data).to eq(Base64.decode64(encrypted_value))
      end
    end
  end

  describe '#decrypt' do
    include_context 'encryption/decryption'

    context 'with AWS KMS provider' do
      include_context 'AWS KMS provider'

      it 'returns the correct unencrypted value' do
        encrypted = BSON::Binary.new(Base64.decode64(encrypted_value), :ciphertext)

        result = client_encryption.decrypt(encrypted)
        expect(result).to eq(value)
      end
    end

    context 'with local KMS provider' do
      include_context 'local KMS provider'

      it 'returns the correct unencrypted value' do
        encrypted = BSON::Binary.new(Base64.decode64(encrypted_value), :ciphertext)

        result = client_encryption.decrypt(encrypted)
        expect(result).to eq(value)
      end
    end
  end
end
