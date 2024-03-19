# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "base64"
require "openssl"
require "ipaddr"
require "murmurhash3"
require "securerandom"
require "logstash/plugin_mixins/ecs_compatibility_support"

# Create consistent hashes (fingerprints) of one or more fields and store
# the result in a new field.
#
# This can e.g. be used to create consistent document ids when inserting
# events into Elasticsearch, allowing events in Logstash to cause existing
# documents to be updated rather than new documents to be created.
#
# NOTE: When using any method other than 'UUID', 'PUNCTUATION' or 'MURMUR3'
# you must set the key, otherwise the plugin will raise an exception
#
# NOTE: When the `target` option is set to `UUID` the result won't be
# a consistent hash but a random
# https://en.wikipedia.org/wiki/Universally_unique_identifier[UUID].
# To generate UUIDs, prefer the <<plugins-filters-uuid,uuid filter>>.
class LogStash::Filters::Fingerprint < LogStash::Filters::Base

  ##
  # Logstash 8+ has variable-length serialization of timestamps
  # that do not include subsecond info for whole-second timestamps.
  # For backward-compatibility we refine the implementation to use
  # our own three-decimal-place formatter for whole-second
  # timestamps.
  if LOGSTASH_VERSION.split('.').first.to_i >= 8
    module MinimumSerializationLengthTimestamp
      THREE_DECIMAL_INSTANT_FORMATTER = java.time.format.DateTimeFormatterBuilder.new.appendInstant(3).toFormatter
      refine LogStash::Timestamp do
        def to_s
          return super unless nsec == 0
          THREE_DECIMAL_INSTANT_FORMATTER.format(to_java.toInstant)
        end
      end
    end
    using MinimumSerializationLengthTimestamp
  end

  INTEGER_MAX_32BIT = (1 << 31) - 1
  INTEGER_MIN_32BIT = -(1 << 31)

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  config_name "fingerprint"

  # The name(s) of the source field(s) whose contents will be used
  # to create the fingerprint. If an array is given, see the
  # `concatenate_sources` option.
  config :source, :validate => :array, :default => 'message'

  # The name of the field where the generated fingerprint will be stored.
  # Any current contents of that field will be overwritten.
  config :target, :validate => :string

  # When used with the `IPV4_NETWORK` method fill in the subnet prefix length.
  # With other methods, optionally fill in the HMAC key.
  config :key, :validate => :password

  # When set to `true`, the `SHA1`, `SHA256`, `SHA384`, `SHA512`, `MD5` and `MURMUR3_128` fingerprint
  # methods will produce base64 encoded rather than hex encoded strings.
  config :base64encode, :validate => :boolean, :default => false

  # The fingerprint method to use.
  #
  # If set to `SHA1`, `SHA256`, `SHA384`, `SHA512`, or `MD5` and a key is set,
  # the cryptographic hash function with the same name will be used to generate
  # the fingerprint. When a key set, the keyed-hash (HMAC) digest function will
  # be used.
  #
  # If set to `MURMUR3` or `MURMUR3_128` the non-cryptographic MurmurHash
  # function (either the 32-bit or 128-bit implementation, respectively)
  # will be used.
  #
  # If set to `IPV4_NETWORK` the input data needs to be a IPv4 address and
  # the hash value will be the masked-out address using the number of bits
  # specified in the `key` option. For example, with "1.2.3.4" as the input
  # and `key` set to 16, the hash becomes "1.2.0.0".
  #
  # If set to `PUNCTUATION`, all non-punctuation characters will be removed
  # from the input string.
  #
  # If set to `UUID`, a
  # https://en.wikipedia.org/wiki/Universally_unique_identifier[UUID] will
  # be generated. The result will be random and thus not a consistent hash.
  config :method, :validate => ['SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', "MURMUR3", "MURMUR3_128", "IPV4_NETWORK", "UUID", "PUNCTUATION"], :required => true, :default => 'SHA1'

  # When set to `true` and `method` isn't `UUID` or `PUNCTUATION`, the
  # plugin concatenates the names and values of all fields given in the
  # `source` option into one string (like the old checksum filter) before
  # doing the fingerprint computation. If `false` and multiple source
  # fields are given, the target field will be an array with fingerprints
  # of the source fields given.
  config :concatenate_sources, :validate => :boolean, :default => false

  # When set to `true` and `method` isn't `UUID` or `PUNCTUATION`, the 
  # plugin concatenates the names and values of all fields in the event 
  # without having to proide the field names in the `source` attribute
  config :concatenate_all_fields, :validate => :boolean, :default => false

  def initialize(*params)
    super
    @target ||= ecs_select[disabled: 'fingerprint', v1: '[event][hash]']
  end

  def register
    # convert to symbol for faster comparisons
    @method = @method.to_sym

    # require any library and set the fingerprint function
    case @method
    when :IPV4_NETWORK
      if @key.nil?
        raise LogStash::ConfigurationError, I18n.t(
          "logstash.runner.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "fingerprint",
          :error => "Key value is empty. please fill in a subnet prefix length"
        )
      end
      class << self; alias_method :fingerprint, :fingerprint_ipv4_network; end
    when :MURMUR3
      class << self; alias_method :fingerprint, :fingerprint_murmur3; end
    when :MURMUR3_128
      class << self; alias_method :fingerprint, :fingerprint_murmur3_128; end
    when :UUID
      # nothing
    when :PUNCTUATION
      # nothing
    else
      # force the resolution of OpenSSL class to avoid errors when loaded in multi-threaded
      # #fingerprint_openssl method to instantiate the appropriate digest class.
      # https://github.com/logstash-plugins/logstash-filter-fingerprint/issues/75
      select_digest(@method)
      class << self; alias_method :fingerprint, :fingerprint_openssl; end
    end
  end

  def filter(event)
    case @method
    when :UUID
      event.set(@target, SecureRandom.uuid)
    when :PUNCTUATION
      @source.sort.each do |field|
        next unless event.include?(field)
        # In order to keep some backwards compatibility we should use the unicode version
        # of the regexp because the POSIX one ([[:punct:]]) left some unwanted characters unfiltered (Symbols).
        # gsub(/[^[:punct:]]/,'') should be equivalent to gsub(/[^[\p{P}\p{S}]]/,''), but not 100% in JRuby.
        event.set(@target, event.get(field).gsub(/[^[\p{P}\p{S}]]/,''))
      end
    else
      if @concatenate_sources || @concatenate_all_fields
        to_string = ""
        if @concatenate_all_fields
          deep_sort_hashes(event.to_hash).each do |k,v|
            # Force encoding to UTF-8 to get around https://github.com/jruby/jruby/issues/6748
            to_string << "|#{k}|#{v}".force_encoding("UTF-8")
          end
        else
          @source.sort.each do |k|
            # Force encoding to UTF-8 to get around https://github.com/jruby/jruby/issues/6748
            to_string << "|#{k}|#{deep_sort_hashes(event.get(k))}".force_encoding("UTF-8")
          end
        end
        to_string << "|"
        @logger.debug? && @logger.debug("String built", :to_checksum => to_string)
        event.set(@target, fingerprint(to_string))
      else
        @source.each do |field|
          next unless event.include?(field)
          if event.get(field).is_a?(Array)
            event.set(@target, event.get(field).collect { |v| fingerprint(deep_sort_hashes(v)) })
          else
            event.set(@target, fingerprint(deep_sort_hashes(event.get(field))))
          end
        end
      end
    end
    filter_matched(event)
  end

  private
  def deep_sort_hashes(object)
    case object
    when Hash
      sorted_hash = Hash.new
      object.sort.each do |sorted_key, value|
        sorted_hash[sorted_key] = deep_sort_hashes(value)
      end
      sorted_hash
    when Array
      object.map {|element| deep_sort_hashes(element) }
    else
      object
    end
  end

  def fingerprint_ipv4_network(ip_string)
    # in JRuby 1.7.11 outputs as US-ASCII
    IPAddr.new(ip_string).mask(@key.value.to_i).to_s.force_encoding(Encoding::UTF_8)
  end

  def fingerprint_openssl(data)
    # since OpenSSL::Digest instances aren't thread safe, we must ensure that
    # each pipeline worker thread gets its own instance.
    # Also, since a logstash pipeline may contain multiple fingerprint filters
    # we must include the id in the thread local variable name, so that we can
    # store multiple digest instances
    digest_string = "digest-#{id}"
    unless Thread.current[digest_string]
      digest_class = select_digest(@method)
      Thread.current[digest_string] = digest_class.new
    end
    digest = Thread.current[digest_string]
    # in JRuby 1.7.11 outputs as ASCII-8BIT
    if @key.nil?
      if @base64encode
        digest.base64digest(data.to_s).force_encoding(Encoding::UTF_8)
      else
        digest.hexdigest(data.to_s).force_encoding(Encoding::UTF_8)
      end
    else
      if @base64encode
        hash = OpenSSL::HMAC.digest(digest, @key.value, data.to_s)
        Base64.strict_encode64(hash).force_encoding(Encoding::UTF_8)
      else
        OpenSSL::HMAC.hexdigest(digest, @key.value, data.to_s).force_encoding(Encoding::UTF_8)
      end
    end
  end

  def fingerprint_murmur3(value)
    case value
    when Integer
      MurmurHash3::V32.int64_hash(value)
    else
      MurmurHash3::V32.str_hash(value.to_s)
    end
  end

  def fingerprint_murmur3_128(value)
    if value.is_a?(Integer)
      if (INTEGER_MIN_32BIT <= value) && (value <= INTEGER_MAX_32BIT)
        if @base64encode
          [MurmurHash3::V128.int32_hash(value, 2).pack("L*")].pack("m").chomp!
        else
          MurmurHash3::V128.int32_hash(value, 2).pack("L*").unpack("H*")[0]
        end
      else
        if @base64encode
          [MurmurHash3::V128.int64_hash(value, 2).pack("L*")].pack("m").chomp!
        else
          MurmurHash3::V128.int64_hash(value, 2).pack("L*").unpack("H*")[0]
        end
      end
    else
      if @base64encode
        MurmurHash3::V128.str_base64digest(value.to_s, 2)
      else
        MurmurHash3::V128.str_hexdigest(value.to_s, 2)
      end
    end
  end

  # Return Class reference more appropriate for the method.
  def select_digest(method)
    case method
    when :SHA1
      OpenSSL::Digest::SHA1
    when :SHA256
      OpenSSL::Digest::SHA256
    when :SHA384
      OpenSSL::Digest::SHA384
    when :SHA512
      OpenSSL::Digest::SHA512
    when :MD5
      OpenSSL::Digest::MD5
    else
      # we really should never get here
      raise(LogStash::ConfigurationError, "Unknown digest for method=#{method.to_s}")
    end
  end
end
