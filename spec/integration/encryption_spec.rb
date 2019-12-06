require 'spec_helper'
require 'base64'

describe 'Auto Encryption' do
  require_libmongocrypt

  let(:client) { ClientRegistry.instance.new_local_client(['localhost:27017']) }

  context 'with local KMS provider' do
    it 'encrypts a command inserted into the database' do
      schema_map = File.read('spec/mongo/crypt/data/schema_map.json')

      auto_encryption_options = {
        kms_providers: { local: { key: Base64.encode64("ru\xfe\x00" * 24) } },
        key_vault_namespace: 'admin.keys',
        schema_map: schema_map
      }

      client = new_local_client([SpecConfig.instance.addresses.first], { auto_encryption_options: auto_encryption_options })
      byebug
      # client.use(:test)[:users].insert_one({ ssn: '123-456-7890' })

      # TODO: Check that you can't get the value back with a different client
    end
  end
end