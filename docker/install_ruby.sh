#!/bin/sh

set -eux

# rbenv - https://github.com/rbenv/rbenv#how-it-works
git clone --depth 1 --branch v1.1.1 https://github.com/rbenv/rbenv.git ~/.rbenv
cd ~/.rbenv && src/configure && make -C src && cd -
echo 'export PATH=~/.rbenv/bin:$PATH' >> ~/.bash_profile
echo 'eval "$(rbenv init -)"' >> ~/.bash_profile
source ~/.bash_profile

# rbenv plugins

## ruby-build - https://github.com/rbenv/ruby-build#readme
git clone --depth 1 --branch v20171226 https://github.com/rbenv/ruby-build.git "$(rbenv root)"/plugins/ruby-build

## rbenv-communal-gems https://github.com/tpope/rbenv-communal-gems
git clone --depth 1 --branch v1.0.1 git://github.com/tpope/rbenv-communal-gems.git "$(rbenv root)"/plugins/rbenv-communal-gems

make install-ruby

# Check rbenv and ruby installation
curl -fsSL https://github.com/rbenv/rbenv-installer/raw/master/bin/rbenv-doctor | bash