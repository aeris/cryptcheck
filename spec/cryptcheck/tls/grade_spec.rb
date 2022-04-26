module CryptCheck
  module Tls
    describe Grade do
      describe '#grade' do
        def obj(trust: true, valid: true, **states)
          Class.new do
            def initialize(trust, valid, states)
              @trust, @valid, @states = trust, valid, states
            end

            include Grade

            def trusted?
              @trust
            end

            def valid?
              @valid
            end

            def states
              State.empty.merge @states
            end
          end.new trust, valid, states
        end

        it 'must return :V if not valid' do
          obj = obj valid:   false, critical: { foo: false, bar: nil },
                    error:   { foo: false, bar: nil },
                    warning: { foo: false, bar: nil },
                    good:    { foo: nil, bar: true },
                    great:   { foo: nil, bar: true },
                    best:    { foo: nil, bar: true }
          expect(obj.grade).to eq :V
        end

        it 'must return :T if not trusted' do
          obj = obj trust:   false, critical: { foo: false, bar: nil },
                    error:   { foo: false, bar: nil },
                    warning: { foo: false, bar: nil },
                    good:    { foo: nil, bar: true },
                    great:   { foo: nil, bar: true },
                    best:    { foo: nil, bar: true }
          expect(obj.grade).to eq :T
        end

        it 'must return :G if critical' do
          obj = obj critical: { foo: false, bar: nil, baz: true },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :G
        end

        it 'must return :F if error' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil, baz: true },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :F
        end

        it 'must return :E if warning' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil, baz: true },
                    good:     { foo: nil, bar: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :E
        end

        it 'must return :D if nor good nor bad' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: false, bar: nil },
                    great:    { foo: nil, bar: true },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :D
        end

        it 'must return :C if some good' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: false, bar: nil, baz: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :C
        end

        it 'must return :C+ if all good' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: false, bar: nil },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :'C+'
        end

        it 'must return :B if some great' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: false, bar: nil, baz: true },
                    best:     { foo: true, bar: nil }
          expect(obj.grade).to eq :B
        end

        it 'must return :B+ if all great' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: false, bar: nil }
          expect(obj.grade).to eq :'B+'
        end

        it 'must return :A if some best' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: false, bar: nil, baz: true }
          expect(obj.grade).to eq :A
        end

        it 'must return :A+ if all best' do
          obj = obj critical: { foo: false, bar: nil },
                    error:    { foo: false, bar: nil },
                    warning:  { foo: false, bar: nil },
                    good:     { foo: nil, bar: true },
                    great:    { foo: nil, bar: true },
                    best:     { foo: nil, bar: true }
          expect(obj.grade).to eq :'A+'
        end
      end
    end
  end
end
