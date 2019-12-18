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

      unencrypted_client.use(:test)[:users].create
      # unencrypted_client.use(:test)[:users,
      #   {
      #     'validator' => { '$jsonSchema' => json_schema }
      #   }
      # ].create

      Mongo::Logger.level = Logger::DEBUG
    end

    it 'encrypts a command inserted into the database' do
      insert_one = BSON::Binary.new(Base64.decode64("ASzggCwAAAAAAAAAAAAAAAACW0cZMYWOY3eoqQQkSdBtS9iHC4CSQA27dy6XJGcmTV8EDuhGNnPmbx0EKFTDb0PCSyCjMyuE4nsgmNYgjTaSuw=="), :cyphertext)
      unencrypted_client.use(:test)[:users].insert_one({ ssn: insert_one })

      # {"insert"=>"users", "ordered"=>true, "documents"=>[{"ssn"=><BSON::Binary:0x70349124925980 type=cyphertext data=0x012ce0802c000000...>, "_id"=>BSON::ObjectId('5df95ad0151af3270382b05d')}], "writeConcern"=>{"w"=>"majority"}, "lsid"=>{"id"=><BSON::Binary...
      # {"insert"=>"users", "ordered"=>true, "documents"=>[{"ssn"=><BSON::Binary:0x70349124035320 type=cyphertext data=0x012ce0802c000000...>, "_id"=>BSON::ObjectId('5df95acf151af3270382b05c')}], "writeConcern"=>{"w"=>"majority"},  "lsid"=>{"id"=><BSON::Binary...
      auto_encryption_options = {
        kms_providers: { local: { key: "Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFBMUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk" } },
        key_vault_namespace: 'admin.datakeys',
        schema_map: {
          "test.users" => {
            "properties" => {
              "ssn" => {
                "encrypt" => {
                  "keyId" => [{
                    "$binary" => {
                        "base64" => "LOCALAAAAAAAAAAAAAAAAA==",
                        "subType" => "04"

                        }
                  }],
                  "bsonType" => "string",
                  "algorithm" => "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                }
              }
            },
            "bsonType" => "object"
          }
        }
      }

      client = new_local_client('mongodb://localhost:27017/test', { write_concern: { w: :majority }, auto_encryption_options: auto_encryption_options })
      result = client.use(:test)[:users].insert_one({ ssn: '123-456-7890' })

      result = unencrypted_client.use(:test)[:users].find({ ssn: '123-456-7890' })
      expect(result.count).to eq(0)
    end
  end
end