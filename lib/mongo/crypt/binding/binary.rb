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

require 'ffi'

module Mongo
  module Crypt
    class Binding

      # @api private
      class Binary
        extend FFI::Library

        ffi_lib ENV['LIBMONGOCRYPT_PATH']

        # Returns a pointer to a new mongocrypt_binary_t object
        #
        # @return [ FFI::Pointer ] A pointer to a mongocrypt_binary_t
        attach_function :mongocrypt_binary_new, [], :pointer

        # Returns a pointer to a new mongocrypt_binary_t object wrapping the
        # provided data.
        #
        # @param [ FFI::Pointer ] data A pointer to an array of uint8. This array
        #   is not owned by the mongocrypt_binary_t and must be de-allocated
        #   separately.
        # @param [ Integer ] len The length of the array
        #
        # @return [ FFI::Pointer ] A pointer to a mongocrypt_binary_t
        attach_function :mongocrypt_binary_new_from_data, [:pointer, :int], :pointer


        # Returns a pointer to the byte array referenced by the mongocrypt_binary_t
        #
        # @param [ FFI::Pointer ] binary A pointer to the mongocrypt_binary_t
        #   object
        #
        # @return [ FFI::Pointer ] A pointer to the array of uint8
        attach_function :mongocrypt_binary_data, [:pointer], :pointer

        # Returns the length of the underlying data
        #
        # @param [ FFI::Pointer ] binary A pointer to the mongocrypt_binary_t
        #   object
        #
        # @return [ Integer ] The length of the wrapped array
        attach_function :mongocrypt_binary_len, [:pointer], :int

        # Frees the reference to that mongocrypt_binary_t
        #
        # @param [ FFI::Pointer ] binary A pointer to the mongocrypt_binary_t
        #   object
        attach_function :mongocrypt_binary_destroy, [:pointer], :void

        class << self
          alias :new            :mongocrypt_binary_new
          alias :new_from_data  :mongocrypt_binary_new_from_data
          alias :data           :mongocrypt_binary_data
          alias :length         :mongocrypt_binary_len
          alias :destroy        :mongocrypt_binary_destroy

          # Write data to a mongocrypt_binary_t object
          #
          # @param [ FFI::Pointer ] binary_p A pointer to the mongocrypt_binary_t
          #   object
          # @param [ String ] data The data to write to the binary object
          #
          # @return [ true ] Always true
          # @raise [ ArgumentError ] Raises when trying to write more data
          # than was originally allocated
          def binary_write(binary_p, data)
            # Cannot write a string that's longer than the space currently allocated
            # by the mongocrypt_binary_t object
            data_p = mongocrypt_binary_data(binary_p)
            len = mongocrypt_binary_len(binary_p)

            if len < data.length
              raise ArgumentError.new(
                "Cannot write #{data.length} bytes of data to a Binary object " +
                "that was initialized with #{len} bytes."
              )
            end

            data_p.put_bytes(0, data)

            true
          end

          # Return the data referenced by the mongocrypt_binary_t object
          # as a string
          #
          # @param [ FFI::Pointer ] binary_p A pointer to the mongocrypt_binary_t
          #   object
          #
          # @return [ String ] The underlying byte data as a string
          def binary_to_string(binary_p)
            str_p = mongocrypt_binary_data(binary_p)
            len = mongocrypt_binary_len(binary_p)
            str_p.read_string(len)
          end
        end
      end
    end
  end
end
