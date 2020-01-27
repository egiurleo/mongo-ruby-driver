module CryptHelper
  def self.included(context)
    context.let(:local_kms_provider) { { key: Base64.encode64("ru\xfe\x00" * 24) } }

    context.let(:aws_kms_provider) do
      {
        access_key_id: ENV['FLE_AWS_KEY'],
        secret_access_key: ENV['FLE_AWS_SECRET']
      }
    end

    shared_context 'with local KMS provider' do
      let(:kms_providers) { { local: local_kms_provider } }
    end

    shared_context 'with AWS KMS provider' do
      let(:kms_providers) { { aws: aws_kms_provider } }
    end
  end
end
