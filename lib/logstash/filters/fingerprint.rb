# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "base64"
require "openssl"
require "ipaddr"
require "murmurhash3"
require "securerandom"

#  Fingerprint fields using by replacing values with a consistent hash.
class LogStash::Filters::Fingerprint < LogStash::Filters::Base
  config_name "fingerprint"

  # Source field(s)
  config :source, :validate => :array, :default => 'message'

  # Target field.
  # will overwrite current value of a field if it exists.
  config :target, :validate => :string, :default => 'fingerprint'

  # When used with `IPV4_NETWORK` method fill in the subnet prefix length
  # Not required for `MURMUR3` or `UUID` methods
  # With other methods fill in the `HMAC` key
  config :key, :validate => :string

  # When set to 'true', SHA1', 'SHA256', 'SHA384', 'SHA512' and 'MD5' fingerprint methods will be returned
  # base64 encoded rather than hex encoded.
  config :base64encode, :validate => :boolean, :default => false

  # Fingerprint method
  config :method, :validate => ['SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', "MURMUR3", "IPV4_NETWORK", "UUID", "PUNCTUATION"], :required => true, :default => 'SHA1'

  # When set to `true`, we concatenate the values of all fields into 1 string like the old checksum filter.
  config :concatenate_sources, :validate => :boolean, :default => false

  def register
    # convert to symbol for faster comparisons
    @method = @method.to_sym

    # require any library and set the anonymize function
    case @method
    when :IPV4_NETWORK
      if @key.nil?
        raise LogStash::ConfigurationError, I18n.t(
          "logstash.agent.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "fingerprint",
          :error => "Key value is empty. please fill in a subnet prefix length"
        )
      end
      class << self; alias_method :anonymize, :anonymize_ipv4_network; end
    when :MURMUR3
      class << self; alias_method :anonymize, :anonymize_murmur3; end
    when :UUID
      # nothing
    when :PUNCTUATION
      # nothing
    else
      if @key.nil?
        raise LogStash::ConfigurationError, I18n.t(
          "logstash.agent.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "fingerprint",
          :error => "Key value is empty. Please fill in an encryption key"
        )
      end
      class << self; alias_method :anonymize, :anonymize_openssl; end
      @digest = select_digest(@method)
    end
  end

  def filter(event)
    case @method
    when :UUID
      event[@target] = SecureRandom.uuid
    when :PUNCTUATION
      @source.sort.each do |field|
        next unless event.include?(field)
        # In order to keep some backwards compatibility we should use the unicode version
        # of the regexp because the POSIX one ([[:punct:]]) left some unwanted characters unfiltered (Symbols).
        # gsub(/[^[:punct:]]/,'') should be equivalent to gsub(/[^[\p{P}\p{S}]]/,''), but not 100% in JRuby.
        event[@target] = event[field].gsub(/[^[\p{P}\p{S}]]/,'')
      end
    else
      if @concatenate_sources
        to_string = ""
        @source.sort.each do |k|
          to_string << "|#{k}|#{event[k]}"
        end
        to_string << "|"
        @logger.debug? && @logger.debug("String built", :to_checksum => to_string)
        event[@target] = anonymize(to_string)
      else
        @source.each do |field|
          next unless event.include?(field)
          if event[field].is_a?(Array)
            event[@target] = event[field].collect { |v| anonymize(v) }
          else
            event[@target] = anonymize(event[field])
          end
        end
      end
    end
  end

  private

  def anonymize_ipv4_network(ip_string)
    # in JRuby 1.7.11 outputs as US-ASCII
    IPAddr.new(ip_string).mask(@key.to_i).to_s.force_encoding(Encoding::UTF_8)
  end

  def anonymize_openssl(data)
    # in JRuby 1.7.11 outputs as ASCII-8BIT
    if @base64encode
      hash  = OpenSSL::HMAC.digest(@digest, @key, data.to_s)
      Base64.strict_encode64(hash).force_encoding(Encoding::UTF_8)
    else
      OpenSSL::HMAC.hexdigest(@digest, @key, data.to_s).force_encoding(Encoding::UTF_8)
    end
  end

  def anonymize_murmur3(value)
    case value
    when Fixnum
      MurmurHash3::V32.int_hash(value)
    else
      MurmurHash3::V32.str_hash(value.to_s)
    end
  end

  def select_digest(method)
    case method
    when :SHA1
      OpenSSL::Digest::SHA1.new
    when :SHA256
      OpenSSL::Digest::SHA256.new
    when :SHA384
      OpenSSL::Digest::SHA384.new
    when :SHA512
      OpenSSL::Digest::SHA512.new
    when :MD5
      OpenSSL::Digest::MD5.new
    else
      # we really should never get here
      raise(LogStash::ConfigurationError, "Unknown digest for method=#{method.to_s}")
    end
  end
end
