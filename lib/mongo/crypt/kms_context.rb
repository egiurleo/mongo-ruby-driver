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
    class KMSContext
      # TODO: documentation
      def initialize(kms_ctx_p)
        # The KMSContext pointer is managed by the Context object that
        # created it; it is not the responsibility of this class to
        # de-allocate memory.
        @kms_ctx_p = kms_ctx_p
      end

      # TODO: documentation
      attr_reader :kms_ctx_p

      # TODO: documentation
      def endpoint
        Binding.kms_ctx_endpoint(self)
      end

      # TODO: documentation
      def message
        Binding.kms_ctx_message(self)
      end

      # TODO: documentation
      def bytes_needed
        Binding.kms_ctx_bytes_needed(self)
      end

      # TODO: documentation
      def feed(data)
        Binding.kms_ctx_feed(self, data)
      end
    end
  end
end
