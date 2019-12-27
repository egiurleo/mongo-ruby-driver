require 'spec_helper'
require 'json'

describe 'Auto Encryption' do
  require_libmongocrypt

  let(:auto_encryption_options) do
    {
      kms_providers: { local: { key: "Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFBMUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk" } },
      key_vault_namespace: 'admin.datakeys',
      schema_map: schema_map
    }
  end

  let(:encrypted_client) do
    new_local_client(
      'mongodb://localhost:27017/test',
      {
        write_concern: { w: :majority },
        auto_encryption_options: auto_encryption_options
      }
    )
  end

  let(:unencrypted_client) do
    new_local_client('mongodb://localhost:27017/test', write_concern: { w: :majority })
  end

  let(:admin_client) { unencrypted_client.use(:admin) }

  let(:local_data_key) do
    Utils.parse_extended_json(JSON.parse(File.read('spec/mongo/crypt/data/key_document_local.json')))
  end

  let(:json_schema) do
    Utils.parse_extended_json(JSON.parse(File.read('spec/mongo/crypt/data/schema_map.json')))
  end

  before(:each) do
    unencrypted_client[:users].drop
    admin_client[:datakeys].drop
    admin_client[:datakeys].insert_one(local_data_key)
  end

  describe '#insert' do
    context 'with validator' do
      let(:schema_map) { nil }

      before do
        unencrypted_client[:users,
          {
            'validator' => { '$jsonSchema' => json_schema }
          }
        ].create
      end

      it 'encrypts the command' do
        result = encrypted_client[:users].insert_one({ ssn: '123-456-7890' })
        expect(result).to be_ok

        result = unencrypted_client.use(:test)[:users].find({ ssn: '123-456-7890' })
        expect(result.count).to eq(0)
      end
    end

    context 'with schema map' do
      let(:schema_map) { { "test.users" => json_schema } }

      it 'encrypts the command' do
        result = encrypted_client[:users].insert_one({ ssn: '123-456-7890' })
        expect(result).to be_ok

        result = unencrypted_client.use(:test)[:users].find({ ssn: '123-456-7890' })
        expect(result.count).to eq(0)
      end
    end
  end
end
