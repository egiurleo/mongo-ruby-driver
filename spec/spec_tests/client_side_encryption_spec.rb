require 'spec_helper'

describe 'Client-Side Encryption' do
  # define_transactions_spec_tests(CLIENT_SIDE_ENCRYPTION_TESTS)
  define_transactions_spec_tests([
    'spec/spec_tests/data/client_side_encryption/basic.yml'
  ])
end
