module CryptHelper
  shared_context 'with local KMS provider' do
    let(:kms_providers) do
      { local: { key: Base64.encode64("ru\xfe\x00" * 24) } }
    end
  end

  shared_context 'with AWS KMS provider' do
    let(:kms_providers) do
      {
        aws: {
          access_key_id: ENV['FLE_AWS_KEY'],
          secret_access_key: ENV['FLE_AWS_SECRET']
        }
      }
    end
  end
end
