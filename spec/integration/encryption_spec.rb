require 'spec_helper'
require 'base64'
require 'json'

describe 'Auto Encryption' do
  require_libmongocrypt

  let(:unencrypted_client) { ClientRegistry.instance.new_local_client(['localhost:27017']) }

  def convert_to_binary(obj)
    BSON::Binary.new(obj['$binary'], obj['$type'].to_sym)
  end

  context 'with local KMS provider' do
    before do
      unencrypted_client.use(:test)[:users].drop
      unencrypted_client.use(:admin)[:keys].drop

      data_key = JSON.parse(File.read('spec/mongo/crypt/data/local_data_key.json'))
      data_key['_id'] = convert_to_binary(data_key['_id'])
      data_key['keyMaterial'] = convert_to_binary(data_key['keyMaterial'])

      unencrypted_client.use(:admin)[:keys].insert_one(data_key)
    end

    it 'encrypts a command inserted into the database' do
      schema_map = JSON.parse(File.read('spec/mongo/crypt/data/schema_map.json'))
      # schema_map['admin.users']['encryptMetadata']['keyId'] = convert_to_binary(schema_map['admin.users']['encryptMetadata']['keyId'])

      auto_encryption_options = {
        kms_providers: { local: { key: Base64.encode64("ru\xfe\x00" * 24) } },
        key_vault_namespace: 'admin.keys',
        schema_map: schema_map
      }

      client = new_local_client([SpecConfig.instance.addresses.first], { auto_encryption_options: auto_encryption_options })
      client.use(:test)[:users].insert_one({ name: 'Alan Turing', ssn: '123-456-7890' })

      result = unencrypted_client.use(:test)[:users].find({ name: 'Alan Turing' })
      expect(result.count).to eq(0)
    end
  end
end