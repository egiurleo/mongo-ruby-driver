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

require 'uri'
require 'socket'
require 'openssl'

module Mongo
  module Crypt

    # A class that implements I/O methods between the driver and
    # the MongoDB server or mongocryptd.
    #
    # @api private
    class EncryptionIO
      # Creates a new EncryptionIO object with information about how to connect
      # to the key vault.
      #
      # @param [ Mongo::Client ] key_vault_client A Client connected to the
      #   MongoDB instance containing the key vault
      # @param [ String ] key_vault_namespace The namespace of the key vault
      #   collection in the format database.collection
      #
      # @note This class expects that the key_vault_client and key_vault_namespace
      #   options are not nil and are in the correct format
      def initialize(client, mongocryptd_client, key_vault_client, key_vault_namespace)
        @client = client
        @mongocryptd_client = mongocryptd_client

        key_vault_db_name, key_vault_collection_name = key_vault_namespace.split('.')
        @key_vault_collection = key_vault_client.use(key_vault_db_name)[key_vault_collection_name]
      end

      # Query for keys in the key vault collection using the provided
      # filter
      #
      # @param [ Hash ] filter
      #
      # @return [ Array<Hash> ] The query results
      def find_keys(filter)
        @key_vault_collection.find(filter).to_a
      end

      # Insert a document into the key vault collection
      #
      # @param [ Hash ] document
      #
      # @return [ Mongo::Operation::Insert::Result ] The insertion result
      def insert(document)
        @key_vault_collection.insert_one(document)
      end

      # TODO: documentation
      def collection_info(filter)
        raise "This is bad" unless @client

        result = @client.database.list_collections
        name = filter['name']
        result.find { |r| r['name'] == name }
      end

      # TODO: documentation
      def mark_command(cmd)
        raise "This is bad" unless @mongocryptd_client && @client
        # TODO: reconsider this abstraction
        byebug

        begin
          response = @mongocryptd_client.database.command(cmd)
        rescue Error::NoServerAvailable => e
          raise e if @client.encryption_options[:mongocryptd_bypass_spawn]

          @client.spawn_mongocryptd
          response = @mongocryptd_client.database.command(cmd)
        end

        return response.first
      end

      # TODO: documentation
      def feed_kms(kms_helper)
        endpoint = kms_helper.endpoint
        message = kms_helper.message

        uri = URI(endpoint)

        # ssl_socket = Socket::SSL.new(uri.to_s, uri.port, uri.host, 10, Socket::PF_INET6, { connect_timeout: 10 })
        socket = TCPSocket.open(uri.host, uri.port)
        ssl_context = OpenSSL::SSL::SSLContext.new()
        ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
        ssl_socket.connect

        ssl_socket.puts(message)
        while bytes_needed = kms_helper.bytes_needed > 0 do
          kms_helper.feed(ssl_socket.sysread(bytes_needed))
        end
      end
    end
  end
end
