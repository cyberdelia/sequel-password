# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.authors       = ["Timothée Peignier"]
  gem.email         = ["timothee.peignier@tryphon.org"]
  gem.description   = %q{Sequel plugins to handle password hashing}
  gem.summary       = %q{Add passwords hashing to sequel models.}
  gem.homepage      = "http://rubygems.org/gems/sequel_password"
  gem.license       = 'MIT'

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map { |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "sequel_password"
  gem.require_paths = ["lib"]
  gem.version       = '0.1'

  gem.add_runtime_dependency 'sequel', '~> 4.21', '>= 4.21.0'
  gem.add_runtime_dependency 'bcrypt', '~> 3.1', '>= 3.1.10'
  gem.add_runtime_dependency 'pbkdf2-ruby', '~> 0.2.1'

  gem.add_development_dependency 'rspec', '~> 3.2', '>= 3.2.0'
  gem.add_development_dependency 'simplecov', '~> 0.9.2'
  gem.add_development_dependency 'sqlite3', '~> 1.3', '>= 1.3.10'
end
