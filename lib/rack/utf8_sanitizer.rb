# frozen_string_literal: true

require "uri"
require "stringio"

module Rack
  class UTF8Sanitizer
    StringIO = ::StringIO
    BAD_REQUEST = [400, { "Content-Type" => "text/plain" }, ["Bad Request"]]

    # options[:sanitizable_content_types] Array
    # options[:additional_content_types] Array
    def initialize(app, options={})
      @app = app
      @strategy = build_strategy(options)
      @sanitizable_content_types = options[:sanitizable_content_types]
      @sanitizable_content_types ||= SANITIZABLE_CONTENT_TYPES + (options[:additional_content_types] || [])
    end

    def call(env)
      begin
        env = sanitize(env)
      rescue EOFError
        return BAD_REQUEST
      end
      @app.call(env)
    end

    DEFAULT_STRATEGIES = {
      replace: lambda do |input|
        input.
          force_encoding(Encoding::ASCII_8BIT).
          encode!(Encoding::UTF_8,
                  invalid: :replace,
                  undef:   :replace)
        input
      end,
      exception: lambda do |input|
        input.
          force_encoding(Encoding::ASCII_8BIT).
          encode!(Encoding::UTF_8)
        input
      end
    }.freeze

    # https://github.com/rack/rack/blob/main/SPEC.rdoc
    URI_FIELDS  = %w(
        SCRIPT_NAME
        REQUEST_PATH REQUEST_URI PATH_INFO
        QUERY_STRING
        HTTP_REFERER
        ORIGINAL_FULLPATH
        ORIGINAL_SCRIPT_NAME
        SERVER_NAME
    ).freeze

    SANITIZABLE_CONTENT_TYPES = %w(
      text/plain
      application/x-www-form-urlencoded
      application/json
      text/javascript
    ).freeze

    URI_ENCODED_CONTENT_TYPES = %w(
      application/x-www-form-urlencoded
    ).freeze

    def sanitize(env)
      sanitize_rack_input(env)
      sanitize_cookies(env)
      env.each do |key, value|
        if URI_FIELDS.include?(key)
          if value.frozen?
            env[key] = sanitize_uri_encoded_string(value.dup).freeze
          else
            env[key] = sanitize_uri_encoded_string(value)
          end
        elsif key.to_s.start_with?("HTTP_")
          # Just sanitize the headers and leave them in UTF-8. There is
          # no reason to have UTF-8 in headers, but if it's valid, let it be.
          if value.frozen?
            env[key] = sanitize_string(value.dup).freeze
          else
            env[key] = sanitize_string(value)
          end
        end
      end
    end

    private

    def build_strategy(options)
      strategy = options.fetch(:strategy) { :replace }

      return strategy unless DEFAULT_STRATEGIES.key?(strategy)

      DEFAULT_STRATEGIES[strategy]
    end

    def sanitize_rack_input(env)
      # https://github.com/rack/rack/blob/master/lib/rack/request.rb#L42
      # Logic borrowed from Rack::Request#media_type,#media_type_params,#content_charset
      # Ignoring charset in content type.
      content_type   = env['CONTENT_TYPE']
      content_type &&= content_type.split(/\s*[;,]\s*/, 2).first
      content_type &&= content_type.downcase
      return unless @sanitizable_content_types.include?(content_type)
      uri_encoded = URI_ENCODED_CONTENT_TYPES.include?(content_type)

      if env['rack.input']
        env['rack.input'] = SanitizedRackInput.new(
          env['rack.input'],
          env['CONTENT_LENGTH']&.to_i,
          uri_encoded,
          @strategy
        )
      end
    end

    # Cookies need to be split and then sanitized as url encoded strings
    # since the cookie string itself is not url encoded (separated by `;`),
    # and the normal method of `sanitize_uri_encoded_string` would break
    # later cookie parsing in the case that a cookie value contained an
    # encoded `;`.
    def sanitize_cookies(env)
      return unless env['HTTP_COOKIE']

      env['HTTP_COOKIE'] = env['HTTP_COOKIE']
        .split(/[;,] */n)
        .map { |cookie| sanitize_uri_encoded_string(cookie) }
        .join('; ')
    end

    module Sanitizers
      private

      # URI.encode/decode expect the input to be in ASCII-8BIT.
      # However, there could be invalid UTF-8 characters both in
      # raw and percent-encoded form.
      #
      # So, first sanitize the value, then percent-decode it while
      # treating as UTF-8, then sanitize the result and encode it back.
      #
      # The result is guaranteed to be UTF-8-safe.
      def sanitize_uri_encoded_string(input)
        return input if input.nil?
        decoded_value = decode_string(input)
        reencode_string(decoded_value)
      end

      def reencode_string(decoded_value)
        escape_unreserved(
          sanitize_string(decoded_value))
      end

      def decode_string(input)
        unescape_unreserved(
          sanitize_string(input).
            force_encoding(Encoding::ASCII_8BIT))
      end

      # RFC3986, 2.2 states that the characters from 'reserved' group must be
      # protected during normalization (which is what UTF8Sanitizer does).
      #
      # However, the regexp approach used by URI.unescape is not sophisticated
      # enough for our task.
      def unescape_unreserved(input)
        input.gsub(/%([a-f\d]{2})/i) do |encoded|
          decoded = $1.hex.chr

          # This regexp matches all 'unreserved' characters from RFC3986 (2.3),
          # plus all multibyte UTF-8 characters.
          if decoded.match?(/[A-Za-z0-9\-._~\x80-\xFF]/n)
            decoded
          else
            encoded
          end
        end
      end

      # Performs the reverse function of `unescape_unreserved`. Unlike
      # the previous function, we can reuse the logic in URI#encode
      def escape_unreserved(input)
        # This regexp matches unsafe characters, i.e. everything except 'reserved'
        # and 'unreserved' characters from RFC3986 (2.3), and additionally '%',
        # as percent-encoded unreserved characters could be left over from the
        # `unescape_unreserved` invocation.
        #
        # See also URI::REGEXP::PATTERN::{UNRESERVED,RESERVED}.
        URI::DEFAULT_PARSER.escape(input, /[^\-_.!~*'()a-zA-Z\d;\/?:@&=+$,\[\]%]/)
      end

      def sanitize_string(input)
        if input.is_a? String
          input = input.force_encoding(Encoding::UTF_8)

          if input.valid_encoding?
            input
          else
            @strategy.call(input)
          end
        else
          input
        end
      end
    end

    include Sanitizers

    class SanitizedRackInput
      include Sanitizers

      def initialize(original_io, content_length, uri_encoded, strategy)
        @original_io = original_io
        @uri_encoded = uri_encoded
        @content_length = content_length
        @strategy = strategy
        @sanitized_io = nil
      end

      def gets
        sanitized_io.gets
      end

      def read(*args)
        sanitized_io.read(*args)
      end

      def each(&block)
        sanitized_io.each(&block)
      end

      def rewind
        sanitized_io.rewind
      end

      def size
        # StringIO#size is bytesize
        sanitized_io.size
      end

      def close
        @sanitized_io&.close
        @original_io.close if @original_io.respond_to?(:close)
      end

      private

      UTF8_BOM = "\xef\xbb\xbf".b.freeze
      UTF8_BOM_SIZE = UTF8_BOM.bytesize

      def sanitized_io
        @sanitized_io ||= begin
          input = @content_length ? @original_io.read(@content_length) : @original_io.read
          if input.start_with?(UTF8_BOM)
            input = input.byteslice(UTF8_BOM_SIZE..-1)
          end

          input = sanitize_string(input)
          if @uri_encoded
            input = sanitize_uri_encoded_string(input).force_encoding(Encoding::UTF_8)
          end
          StringIO.new(input)
        end
      end
    end
  end
end
