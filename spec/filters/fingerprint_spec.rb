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

  describe "fingerprint string with SHA1 algorithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'SHA1'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "3a5076c520b4b463f43806896ea0b3978d09dcae"
    end
  end

  describe "fingerprint string with SHA1 HMAC algorithm" do
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

  describe "fingerprint string with SHA1 HMAC algorithm on all event fields" do
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

  describe "fingerprint string with SHA1 algorithm and base64 encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'SHA1'
          base64encode => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "OlB2xSC0tGP0OAaJbqCzl40J3K4="
    end
  end

  describe "fingerprint string with SHA256 algorithm and base64url encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'SHA256'
          base64encode => true
          base64url => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "TavKshB2bjXwPncSDmmG1ubUdSsqn_IpgLklPQJggNg="
    end
  end

  describe "fingerprint string with SHA1 HMAC algorithm and base64 encoding" do
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

  describe "fingerprint string with SHA1 HMAC algorithm and base64url encoding" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          key => "longencryptionkey"
          method => 'SHA1'
          base64encode => true
          base64url => true
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "_cYKzEdz3FrFaf-3j8uTyWMHl_Q="
    end
  end

  describe "fingerprint string with SHA256 algorithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'SHA256'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "4dabcab210766e35f03e77120e6986d6e6d4752b2a9ff22980b9253d026080d8"
    end
  end

  describe "fingerprint string with SHA256 HMAC algorithm" do
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

  describe "fingerprint string with SHA256 HMAC algorithm and base64 encoding" do
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

  describe "fingerprint string with SHA384 algorithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'SHA384'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "fd605b0a3af3e04ce0d7a0b0d9c48d67a12dab811f60072e6eae84e35d567793ffb68a1807536f11c90874065c2a4392"
    end
  end

  describe "fingerprint string with SHA384 HMAC algorithm" do
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

  describe "fingerprint string with SHA384 HMAC algorithm and base64 encoding" do
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

  describe "fingerprint string with SHA512 algorithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'SHA512'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "5468e2dc64ea92b617782aae884b35af60041ac9e168a283615b6a462c54c13d42fa9542cce9b7d76a8124ac6616818905e3e5dd35d6e519f77c3b517558639a"
    end
  end

  describe "fingerprint string with SHA512 HMAC algorithm" do
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

  describe "fingerprint string with SHA512 HMAC algorithm and base64 encoding" do
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

  describe "fingerprint string with MD5 algorithm" do
    config <<-CONFIG
      filter {
        fingerprint {
          source => ["clientip"]
          method => 'MD5'
        }
      }
    CONFIG

    sample("clientip" => "123.123.123.123") do
      insist { subject.get("fingerprint") } == "ccdd8d3d940a01b2fb3258c059924c0d"
    end
  end

  describe "fingerprint string with MD5 HMAC algorithm" do
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

  describe "fingerprint string with MD5 HMAC algorithm and base64 encoding" do
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
