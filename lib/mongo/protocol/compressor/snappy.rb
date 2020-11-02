# Copyright (C) 2020 MongoDB Inc.
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

# begin
  require 'snappy'
# rescue LoadError
#   raise LoadError, "Cannot use snappy compression because the snappy gem has " \
#     "not been installed. Put \"gem 'snappy'\" in your Gemfile and run " \
#     "\"bundle install\" to install the snappy gem"
# end


module Mongo
  module Protocol
    module Compressor
      class Snappy
        def compress(buffer)
          ::Snappy.deflate(buffer.to_s).force_encoding(BSON::BINARY)
        end

        def decompress(compressed_message)
          BSON::ByteBuffer.new(::Snappy.inflate(compressed_message))
        end
      end
    end
  end
end
