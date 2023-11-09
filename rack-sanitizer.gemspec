# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.name          = "rack-sanitizer"
  gem.version       = '2.0.0'
  gem.authors       = ["Jean Boussier", "whitequark"]
  gem.license       = "MIT"
  gem.email         = ["jean.boussier@gmail.org"]
  gem.description   = %{Rack::Sanitizer is a Rack middleware which cleans up } <<
                      %{invalid UTF8 characters in request URI and headers.}
  gem.summary       = "It is a mordernized and optimized fork of rack-utf8_sanitizer"
  gem.homepage      = "http://github.com/Shopify/rack-sanitizer"

  gem.files         = `git ls-files`.split($/)
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.metadata["allowed_push_host"] = "https://rubygems.org/"

  gem.required_ruby_version = '>= 2.5'

  gem.add_dependency             "rack", '>= 1.0', '< 4.0'

  gem.add_development_dependency "bacon"
  gem.add_development_dependency "bacon-colored_output"
  gem.add_development_dependency "rake"
end
