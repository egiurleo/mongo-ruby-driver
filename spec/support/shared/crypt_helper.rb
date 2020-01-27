module CryptHelper
  def self.included(context)
    context.let(:local_kms_provider) do
      {
        key: "Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFB" +
        "MUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk"
      }
    end

    context.let(:aws_kms_provider) do
      {
        access_key_id: ENV['FLE_AWS_KEY'],
        secret_access_key: ENV['FLE_AWS_SECRET']
      }
    end

    context.let(:aws_masterkey) do
      {
        region: 'us-east-1',
        key: 'arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0'
      }
    end

    context.let(:aws_endpoint) do
      'kms.us-east-1.amazonaws.com'
    end
  end

  shared_context 'with local KMS provider' do
    let(:kms_providers) { { local: local_kms_provider } }
    let(:kms_provider) { 'local' }

    let(:data_key) do
      BSON::ExtJSON.parse(File.read('spec/mongo/crypt/data/key_document_local.json'))
    end

    let(:schema_map) do
      BSON::ExtJSON.parse(File.read('spec/mongo/crypt/data/schema_map_local.json'))
    end
  end

  shared_context 'with AWS KMS provider' do
    let(:kms_providers) { { aws: aws_kms_provider } }
    let(:kms_provider) { 'aws' }

    let(:data_key) do
      BSON::ExtJSON.parse(File.read('spec/mongo/crypt/data/key_document_aws.json'))
    end

    let(:schema_map) do
      BSON::ExtJSON.parse(File.read('spec/mongo/crypt/data/schema_map_aws.json'))
    end
  end
end
