require 'spec_helper'
require 'base64'
require 'json'
require 'date'

describe 'Auto Encryption' do
  require_libmongocrypt

  let(:unencrypted_client) { ClientRegistry.instance.new_local_client(['localhost:27017'], write_concern: { w: :majority }) }

  let(:json_schema) do
    schema_map = JSON.parse(File.read('spec/mongo/crypt/data/schema_map.json'))
    schema_map['properties']['ssn']['encrypt']['keyId'][0] = convert_to_binary(schema_map['properties']['ssn']['encrypt']['keyId'][0])

    schema_map
  end

  def convert_to_binary(obj)
    id = Base64.decode64(obj['$binary']['base64'])
    type = case obj['$binary']['subType']
    when '04'
      :uuid
    when '00'
      :generic
    end

    BSON::Binary.new(id, type.to_sym)
  end

  def convert_to_datetime(obj)
    DateTime.strptime(obj['$date']['$numberLong'], '%Q')
  end

  context 'with local KMS provider' do
    before do
      unencrypted_client.use(:test)[:users].drop
      unencrypted_client.use(:admin)[:datakeys].drop

      data_key = JSON.parse(File.read('spec/mongo/crypt/data/local_data_key.json'))
      data_key['_id'] = convert_to_binary(data_key['_id'])
      data_key['keyMaterial'] = convert_to_binary(data_key['keyMaterial'])
      data_key['creationDate'] = convert_to_datetime(data_key['creationDate'])
      data_key['updateDate'] = convert_to_datetime(data_key['updateDate'])

      unencrypted_client.use(:admin)[:datakeys].insert_one(data_key)

      unencrypted_client.use(:test)[:users,
        {
          'validator' => { '$jsonSchema' => json_schema }
        }
      ].create
    end

    it 'encrypts a command inserted into the database' do
      new_json_schema = json_schema.dup
      new_json_schema['properties']['ssn']['encrypt']['algorithm'] = 'fake algorithm'
      auto_encryption_options = {
        kms_providers: { local: { key: Base64.encode64("\x00" * 96) } },
        key_vault_namespace: 'admin.datakeys',
        schema_map: { 'test.users' => new_json_schema }
      }

      client = new_local_client('mongodb://localhost:27017/test', { write_concern: { w: :majority }, auto_encryption_options: auto_encryption_options })
      result = client.use(:test)[:users].insert_one({ ssn: '123-456-7890' })

      result = unencrypted_client.use(:test)[:users].find({ name: 'Alan Turing' })
      expect(result.count).to eq(0)
    end
  end
end