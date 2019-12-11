require 'spec_helper'
require 'base64'
require 'json'

describe 'Auto Encryption' do
  require_libmongocrypt

  let(:unencrypted_client) { ClientRegistry.instance.new_local_client(['localhost:27017']) }

  context 'with local KMS provider' do
    it 'encrypts a command inserted into the database' do
      schema_map = JSON.parse(File.read('spec/mongo/crypt/data/schema_map.json'))

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