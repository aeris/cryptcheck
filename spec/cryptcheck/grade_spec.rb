module CryptCheck
  describe Grade do
    describe '#compare' do
      it 'must return correct order' do
        expect(Grade.compare('A', 'B')).to be -1
        expect(Grade.compare('A', 'A')).to be 0
        expect(Grade.compare('B', 'A')).to be 1

        expect(Grade.compare('A+', 'A')).to be -1
        expect(Grade.compare('A+', 'A+')).to be 0
        expect(Grade.compare('A', 'A+')).to be 1

        expected = %i[A+ A  B+ B C+ C D E F G V T X]
        sorted   = expected.shuffle
                           .sort &Grade.method(:compare)
        expect(sorted).to eq expected
      end
    end
  end
end
