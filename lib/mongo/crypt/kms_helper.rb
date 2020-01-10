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

    # TODO: documentation
    class KMSHelper
      # TODO: documentation
      def initialize(kms_ctx)
        @kms_ctx = kms_ctx
      end

      # TODO: endpoint
      def endpoint
        # FFI::MemoryPointer automatically frees memory when it goes out of scope
        ptr = FFI::MemoryPointer.new(:pointer, 1)
        Binding.mongocrypt_kms_ctx_endpoint(@kms_ctx, ptr)

        str_ptr = ptr.read_pointer
        str_ptr.null? ? nil : str_ptr.read_string.force_encoding('UTF-8')
      end

      # TODO: documentation
      def message
        binary = Binary.new

        success = Binding.mongocrypt_kms_ctx_message(@kms_ctx, binary.ref)
        raise_from_status unless success

        binary.to_string
      end

      # TODO: documentation
      def bytes_needed
        Binding.mongocrypt_kms_ctx_bytes_needed(@kms_ctx)
      end

      # TODO: documentation
      def feed(data)
        binary = Binary.new(data)

        success = Binding.mongocrypt_kms_ctx_feed(@kms_ctx, binary.ref)
        raise_from_status unless success

        true
      end

      private

      def raise_from_status
        status = Status.new

        Binding.mongocrypt_kms_ctx_status(@kms_ctx, status.ref)
        status.raise_crypt_error
      end
    end
  end
end
