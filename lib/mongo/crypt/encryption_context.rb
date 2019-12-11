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

    # A Context object initialized for auto encryption
    class EncryptionContext < Context

      # TODO: documentation
      def initialize(mongocrypt, io, db_name, cmd)
        super(mongocrypt, io)

        @db_name = db_name
        @cmd = cmd

        initialize_ctx
      end

      private

      # TODO: documentation
      def initialize_ctx
        binary = Binary.new(@cmd.to_bson.to_s)
        success = Binding.mongocrypt_ctx_encrypt_init(@ctx, @db_name, -1, binary.ref)

        raise_from_status unless success
      end
    end
  end
end
