# Copyright (C) 2019 MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module Mongo
  module Crypt

    # A Context object initialized specifically for the purpose of creating
    # a data key in the key managemenet system.
    #
    # @api private
    class DataKeyContext < Context

      # Create a new DataKeyContext object
      #
      # @param [ Mongo::Crypt::Handle ] mongocrypt a Handle that
      #   wraps a mongocrypt_t object used to create a new mongocrypt_ctx_t
      # @param [ Mongo::Crypt::EncryptionIO ] io An object that performs all
      #   driver I/O on behalf of libmongocrypt
      # @param [ String ] kms_provider The KMS provider to use. Options are
      #   "aws" and "local".
      def initialize(mongocrypt, io, kms_provider, options={})
        unless ['aws', 'local'].include?(kms_provider)
          raise ArgumentError.new('#{kms_provider} is an invalid kms provider. Valid options are "aws" and "local"')
        end

        @options = options

        super(mongocrypt, io)

        set_local_master_key if kms_provider == 'local'
        set_aws_master_key if kms_provider == 'aws'

        initialize_ctx
      end

      private

      # Configures the underlying mongocrypt_ctx_t object to accept local
      # KMS options
      def set_local_master_key
        success = Binding.mongocrypt_ctx_setopt_masterkey_local(@ctx)
        raise_from_status unless success
      end

      # Configure the underlying mongocrypt_ctx_t object to accept AWS
      # KMS options
      def set_aws_master_key
        unless @options[:masterkey]
          raise ArgumentError.new('The :masterkey option cannot be nil')
        end

        unless @options[:masterkey].is_a?(Hash)
          raise ArgumentError.new('The :masterkey option must be a Hash')
        end

        # TODO: better error message
        unless @options[:masterkey][:region] && @options[:masterkey][:region].is_a?(String)
          raise ArgumentError.new('The :masterkey option must contain a region specified as a string')
        end

        # TODO: better error message
        unless @options[:masterkey][:key] && @options[:masterkey][:key].is_a?(String)
          raise ArgumentError.new('The :masterkey option must contain a key specified as a string')
        end

        success = Binding.mongocrypt_ctx_setopt_masterkey_aws(
          @ctx,
          @options[:masterkey][:region],
          -1,
          @options[:masterkey][:key],
          -1
        )
        raise_from_status unless success
      end

      # Initializes the underlying mongocrypt_ctx_t object
      def initialize_ctx
        success = Binding.mongocrypt_ctx_datakey_init(@ctx)
        raise_from_status unless success
      end
    end
  end
end
