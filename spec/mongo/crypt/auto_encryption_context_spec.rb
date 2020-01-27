require 'mongo'
require 'support/lite_constraints'
require 'support/shared/crypt_helper'

RSpec.configure do |config|
  config.extend(LiteConstraints)
  config.include(CryptHelper)
end

describe Mongo::Crypt::AutoEncryptionContext do
  require_libmongocrypt

  let(:mongocrypt) { Mongo::Crypt::Handle.new(kms_providers, logger: logger) }
  let(:context) { described_class.new(mongocrypt, io, db_name, command) }

  let(:logger) { nil }

  let(:io) { double("Mongo::ClientEncryption::IO") }
  let(:db_name) { 'admin' }
  let(:command) do
    {
      "find": "test",
      "filter": {
          "ssn": "457-55-5462"
      }
    }
  end

  include_context 'with local KMS provider'

  describe '#initialize' do
    context 'with invalid command' do
      let(:command) do
        {
          incorrect_key: 'value'
        }
      end

      it 'raises an exception' do
        expect do
          context
        end.to raise_error(/command not supported for auto encryption: incorrect_key/)
      end
    end

    context 'with valid options' do
      context 'when mongocrypt is initialized with local KMS provider options' do
        it 'initializes context' do
          expect do
            context
          end.not_to raise_error
        end
      end

      context 'when mongocrypt is initialized with AWS KMS provider options' do
        include_context 'with AWS KMS provider'

        it 'initializes context' do
          expect do
            context
          end.not_to raise_error
        end
      end

      context 'with verbose logging' do
        before(:all) do
          # Logging from libmongocrypt requires the C library to be built with the -DENABLE_TRACE=ON
          # option; none of the pre-built packages on Evergreen have been built with logging enabled.
          #
          # It is still useful to be able to run these tests locally to confirm that logging is working
          # while debugging any problems.
          #
          # For now, skip this test by default and revisit once we have determined how we want to
          # package libmongocrypt with the Ruby driver (see: https://jira.mongodb.org/browse/RUBY-1966)
          skip "These tests require libmongocrypt to be built with the '-DENABLE_TRACE=ON' cmake option." +
            " They also require the MONGOCRYPT_TRACE environment variable to be set to 'ON'."
        end

        let(:logger) do
          ::Logger.new($stdout).tap do |logger|
            logger.level = ::Logger::DEBUG
          end
        end

        it 'receives log messages from libmongocrypt' do
          expect(logger).to receive(:debug).with(/mongocrypt_ctx_encrypt_init/)
          context
        end
      end
    end
  end
end
