# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/fingerprint"

describe LogStash::Filters::Fingerprint do

  describe "fingerprint ipaddress with IPV4_NETWORK method" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => "IPV4_NETWORK"
          key => 24
        }
      }
    CONFIG

    sample("clientip" => "233.255.13.44") do
      insist { subject.get("fingerprint") } == "233.255.13.0"
    end
  end

  describe "fingerprint string with MURMUR3 method" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => "MURMUR3"
        }
      }
    CONFIG

    sample("clientip" => "123.52.122.33") do
      insist { subject.get("fingerprint") } == 1541804874
    end
  end

  describe "fingerprint string with SHA1 alogrithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA1'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "fdc60acc4773dc5ac569ffb78fcb93c9630797f4"
    end
  end

  describe "fingerprint string with SHA1 alogrithm on all event fields" do
    config <<-CONFIG
      filter {
        fingerprint {
          concatenate_all_fields => true
          key => "longencryptionkey"
          method => 'SHA1'
        }
      }
    CONFIG

    # The @timestamp field is specified in this sample event as we need the event contents to be constant for the tests
    sample("@timestamp" => "2017-07-26T14:44:27.064Z", "clientip" => "123.123.123.123", "message" => "This is a test message", "log_level" => "INFO", "offset" => 123456789, "type" => "test") do
      insist { subject.get("fingerprint") } == "d7c617f4d40b2cb677a7003af68a41c415f58031"
    end
  end

  describe "fingerprint string with SHA1 alogrithm and base64 encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA1'
          base64encode => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "/cYKzEdz3FrFaf+3j8uTyWMHl/Q="
    end
  end

  describe "fingerprint string with SHA256 alogrithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA256'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "345bec3eff242d53b568916c2610b3e393d885d6b96d643f38494fd74bf4a9ca"
    end
  end

  describe "fingerprint string with SHA256 alogrithm and base64 encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA256'
          base64encode => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "NFvsPv8kLVO1aJFsJhCz45PYhda5bWQ/OElP10v0qco="
    end
  end

  describe "fingerprint string with SHA384 alogrithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA384'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "22d4c0e8c4fbcdc4887d2038fca7650f0e2e0e2457ff41c06eb2a980dded6749561c814fe182aff93e2538d18593947a"
    end
  end

  describe "fingerprint string with SHA384 alogrithm and base64 encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA384'
          base64encode => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "ItTA6MT7zcSIfSA4/KdlDw4uDiRX/0HAbrKpgN3tZ0lWHIFP4YKv+T4lONGFk5R6"
    end
  end

  describe "fingerprint string with SHA512 alogrithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA512'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "11c19b326936c08d6c50a3c847d883e5a1362e6a64dd55201a25f2c1ac1b673f7d8bf15b8f112a4978276d573275e3b14166e17246f670c2a539401c5bfdace8"
    end
  end

  describe "fingerprint string with SHA512 alogrithm and base64 encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA512'
          base64encode => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "EcGbMmk2wI1sUKPIR9iD5aE2Lmpk3VUgGiXywawbZz99i/FbjxEqSXgnbVcydeOxQWbhckb2cMKlOUAcW/2s6A=="
    end
  end

  describe "fingerprint string with MD5 alogrithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'MD5'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "9336c879e305c9604a3843fc3e75948f"
    end
  end

  describe "fingerprint string with MD5 alogrithm and base64 encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'MD5'
          base64encode => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "kzbIeeMFyWBKOEP8PnWUjw=="
    end
  end

  describe "Test field with multiple values" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'MD5'
        }
      }
    CONFIG

    sample("clientip" => [ "123.123.123.123", "223.223.223.223" ]) do
      insist { subject.get("fingerprint")} == [ "9336c879e305c9604a3843fc3e75948f", "7a6c66b8d3f42a7d650e3354af508df3" ]
    end
  end

  describe "Concatenate multiple values into 1" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ['field1', 'field2']
          key => "longencryptionkey"
          method => 'MD5'
        }
      }
    CONFIG

    sample("field1" => "test1", "field2" => "test2") do
      insist { subject.get("fingerprint")} == "872da745e45192c2a1d4bf7c1ff8a370"
    end
  end

  describe "PUNCTUATION method" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => 'field1'
          method => 'PUNCTUATION'
        }
      }
    CONFIG

    sample("field1" =>  "PHP Warning:  json_encode() [<a href='function.json-encode'>function.json-encode</a>]: Invalid UTF-8 sequence in argument in /var/www/htdocs/test.php on line 233") do
      insist { subject.get("fingerprint") } == ":_()[<='.-'>.-</>]:-////."
    end

    sample("field1" => "Warning: Ruby(ルビ) is an awesome language.") do
      insist { subject.get("fingerprint") } == ":()."
    end
  end

  context 'Timestamps' do
    epoch_time = Time.at(0).gmtime

    describe 'OpenSSL Fingerprinting' do
      config <<-CONFIG
        filter {
          fingerprint {
            source => ['@timestamp']
            key    => '0123'
            method => 'SHA1'
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time) do
        insist { subject.get("fingerprint") } == '1d5379ec92d86a67cfc642d55aa050ca312d3b9a'
      end
    end

    describe 'MURMUR3 Fingerprinting' do
      config <<-CONFIG
        filter {
          fingerprint {
            source => ['@timestamp']
            method => 'MURMUR3'
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time) do
        insist { subject.get("fingerprint") } == 743372282
      end
    end
  end

  describe "execution triggers addition of fields and tags" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => 'field1'
          method => 'PUNCTUATION'
          add_field => { 'myfield' => 'myvalue' }
          add_tag => ['mytag']
        }
      }
    CONFIG

    sample("field1" => "Hello, World!") do
      insist { subject.get("myfield") } == "myvalue"
      insist { subject.get("tags") } == ["mytag"]
    end
  end

end
