require 'mongo'
require 'support/lite_constraints'

RSpec.configure do |config|
  config.extend(LiteConstraints)
end

describe 'Mongo::Crypt::Binding' do
  describe 'state machine' do
    require_libmongocrypt

    let(:described_class) =

    shared_example 'mongocrypt' do
      it 'runs the state machine' do
        while true do

        end
      end
    end
  end
end