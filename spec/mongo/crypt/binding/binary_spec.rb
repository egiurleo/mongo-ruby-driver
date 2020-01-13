require 'mongo'
require 'support/lite_constraints'

RSpec.configure do |config|
  config.extend(LiteConstraints)
end

describe 'Mongo::Crypt::Binding::Binary' do
  require_libmongocrypt

  let(:described_class) { Mongo::Crypt::Binding::Binary }
  let(:bytes) { [104, 101, 108, 108, 111] }

  let(:bytes_pointer) do
    # FFI::MemoryPointer automatically frees memory when it goes out of scope
    p = FFI::MemoryPointer.new(bytes.size)
    p.write_array_of_type(FFI::TYPE_UINT8, :put_uint8, bytes)
  end

  after do
    described_class.destroy(binary)
  end

  describe '#new' do
    let(:binary) { described_class.new }

    it 'returns a pointer' do
      expect(binary).to be_a_kind_of(FFI::Pointer)
    end
  end

  describe '#new_from_data' do
    let(:binary) { described_class.new_from_data(bytes_pointer, bytes.length) }

    it 'returns a pointer' do
      expect(binary).to be_a_kind_of(FFI::Pointer)
    end
  end

  describe '#data' do
    let(:binary) { described_class.new_from_data(bytes_pointer, bytes.length) }

    it 'returns the pointer to the data' do
      expect(described_class.data(binary)).to eq(bytes_pointer)
    end
  end

  describe '#length' do
    let(:binary) { described_class.new_from_data(bytes_pointer, bytes.length) }

    it 'returns the length of the data' do
      expect(described_class.length(binary)).to eq(bytes.length)
    end
  end
end
