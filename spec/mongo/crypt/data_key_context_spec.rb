require 'mongo'
require 'support/lite_constraints'
require 'base64'

RSpec.configure do |config|
  config.extend(LiteConstraints)
end

describe Mongo::Crypt::DataKeyContext do
  require_libmongocrypt

  let(:mongocrypt) do
    Mongo::Crypt::Handle.new(
      {
        local: { key: Base64.encode64("ru\xfe\x00" * 24) },
        aws: {
          access_key_id: ENV['FLE_AWS_ACCESS_KEY'],
          secret_access_key: ENV['FLE_AWS_SECRET_ACCESS_KEY']
        }
      }
    )
  end

  let(:io) { double("Mongo::Crypt::EncryptionIO") }

  let(:context) { described_class.new(mongocrypt, io, 'local') }

  describe '#initialize' do
    context 'with local kms provider' do
      it 'does not raise an exception' do
        expect do
          context
        end.not_to raise_error
      end
    end

    context 'with aws kms provider' do
      let(:context) { described_class.new(mongocrypt, io, 'aws', options) }

      context 'with empty options' do
        let(:options) { {} }

        it 'raises an exception' do
          expect do
            context
          end.to raise_error(ArgumentError, /:masterkey option cannot be nil/)
        end
      end

      context 'with an invalid masterkey option' do
        let(:options) { { masterkey: 'key' } }

        it 'raises an exception' do
          expect do
            context
          end.to raise_error(ArgumentError, /:masterkey option must be a Hash/)
        end
      end

      context 'where masterkey is an empty hash' do
        let(:options) { { masterkey: {} } }

        it 'raises an exception' do
          expect do
            context
          end.to raise_error(ArgumentError, /:masterkey option must contain a region/)
        end
      end

      context 'with an invalid region option' do
        let(:options) { { masterkey: { region: nil } } }

        it 'raises an exception' do
          expect do
            context
          end.to raise_error(ArgumentError, /:masterkey option must contain a region/)
        end
      end

      context 'with an invalid key option' do
        let(:options) { { masterkey: { region: 'us-east-2', key: nil } } }

        it 'raises an exception' do
          expect do
            context
          end.to raise_error(ArgumentError, /:masterkey option must contain a key/)
        end
      end

      context 'with valid options' do
        let(:options) { { masterkey: { region: 'us-east-2', key: 'arn' } } }

        it 'does not raise an exception' do
          expect do
            context
          end.not_to raise_error
        end
      end
    end
  end

  # This is a simple spec just to test that this method works
  # There should be multiple specs testing the context's state
  #   depending on how it's initialized, etc.
  describe '#state' do
    it 'returns :ready' do
      expect(context.state).to eq(:ready)
    end
  end

  # This is a simple spec just to test the POC case of creating a data key
  # There should be specs testing each state, as well as integration tests
  #   to test that the state machine returns the correct result under various
  #   conditions
  describe '#run_state_machine' do
    it 'creates a data key' do
      expect(context.run_state_machine).to be_a_kind_of(String)
    end
  end
end
