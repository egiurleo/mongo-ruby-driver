require 'spec_helper'

describe 'Client-Side Encryption' do
  # define_transactions_spec_tests(CLIENT_SIDE_ENCRYPTION_TESTS)
  define_transactions_spec_tests([
    'spec/spec_tests/data/client_side_encryption/aggregate.yml',
    # 'spec/spec_tests/data/client_side_encryption/badQueries.yml',
    # 'spec/spec_tests/data/client_side_encryption/badSchema.yml',
    'spec/spec_tests/data/client_side_encryption/basic.yml',
    'spec/spec_tests/data/client_side_encryption/bulk.yml',
    'spec/spec_tests/data/client_side_encryption/bypassAutoEncryption.yml',
    'spec/spec_tests/data/client_side_encryption/bypassedCommand.yml',
    'spec/spec_tests/data/client_side_encryption/count.yml',
    'spec/spec_tests/data/client_side_encryption/countDocuments.yml',
    'spec/spec_tests/data/client_side_encryption/delete.yml',
    'spec/spec_tests/data/client_side_encryption/distinct.yml',
    'spec/spec_tests/data/client_side_encryption/explain.yml',
    'spec/spec_tests/data/client_side_encryption/find.yml',
    'spec/spec_tests/data/client_side_encryption/findOneAndDelete.yml',
    'spec/spec_tests/data/client_side_encryption/findOneAndReplace.yml',
    'spec/spec_tests/data/client_side_encryption/findOneAndUpdate.yml',
    'spec/spec_tests/data/client_side_encryption/getMore.yml',
    'spec/spec_tests/data/client_side_encryption/insert.yml',
    'spec/spec_tests/data/client_side_encryption/keyAltName.yml',
    'spec/spec_tests/data/client_side_encryption/localKMS.yml',
    # 'spec/spec_tests/data/client_side_encryption/localSchema.yml',
    # 'spec/spec_tests/data/client_side_encryption/malformedCiphertext.yml',
    'spec/spec_tests/data/client_side_encryption/maxWireVersion.yml',
    'spec/spec_tests/data/client_side_encryption/missingKey.yml',
    'spec/spec_tests/data/client_side_encryption/replaceOne.yml',
    # 'spec/spec_tests/data/client_side_encryption/types.yml',
    'spec/spec_tests/data/client_side_encryption/unsupportedCommand.yml',
    'spec/spec_tests/data/client_side_encryption/updateMany.yml',
    # 'spec/spec_tests/data/client_side_encryption/updateOne.yml',
  ])
end
