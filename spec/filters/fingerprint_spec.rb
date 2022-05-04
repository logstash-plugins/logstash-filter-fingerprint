# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/fingerprint"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

describe LogStash::Filters::Fingerprint, :ecs_compatibility_support, :aggregate_failures do
  ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|

    let(:plugin) { described_class.new(config) }
    let(:config) { { "method" => fingerprint_method } }
    let(:fingerprint_method) { "SHA1" } # default
    let(:data) { {} }
    let(:event) { LogStash::Event.new(data) }
    let(:fingerprint) { event.get(ecs_select[disabled: "fingerprint", v1: "[event][hash]"]) }

    before(:each) do
      allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      plugin.register
      plugin.filter(event)
    end

    context "with a string field" do
      let(:data) { {"clientip" => "123.123.123.123" } }
      let(:config) { super().merge("source" => ["clientip" ]) }

      describe "the IPV4_NETWORK method" do
        let(:fingerprint_method) { "IPV4_NETWORK" }
        let(:config) { super().merge("key" => 24) }

        it "fingerprints the ip as the network" do
          expect(fingerprint).to eq("123.123.123.0")
        end
      end

      describe "the MURMUR3 method" do
        let(:fingerprint_method) { "MURMUR3" }

        context "string" do
          it "fingerprints the value" do
            expect(fingerprint).to eq(4013733395)
          end
        end

        context "number" do
          let(:data) { {"clientip" => 123 } }

          it "fingerprints the value" do
            expect(fingerprint).to eq(823512154)
          end
        end
      end

      describe "the MURMUR3_128 method" do
        let(:fingerprint_method) { "MURMUR3_128" }

        context "string hex encoding" do
          it "fingerprints the value" do
            expect(fingerprint).to eq("41cbc4056eed401d091dfbeabf7ea9e0")
          end
        end

        context "string base64 encoding" do
          let(:config) { super().merge("base64encode" => true) }
          it "fingerprints the value" do
            expect(fingerprint).to eq("QcvEBW7tQB0JHfvqv36p4A==")
          end
        end

        context "int32 hex encoding" do
          let(:config) { super().merge("base64encode" => false) }
          let(:data) { {"clientip" => 123 } }

          it "fingerprints the value" do
            expect(fingerprint).to eq("286816c693ac410ed63e1430dcd6f6fe")
          end
        end

        context "int32 base64 encoding" do
          let(:config) { super().merge("base64encode" => true) }
          let(:data) { {"clientip" => 123 } }

          it "fingerprints the value" do
            expect(fingerprint).to eq("KGgWxpOsQQ7WPhQw3Nb2/g==")
          end
        end

        context "int64 hex encoding" do
          let(:config) { super().merge("base64encode" => false) }
          let(:data) { {"clientip" => 2148483647 } }

          it "fingerprints the value" do
            expect(fingerprint).to eq("fdc7699a82556c8c584131f0133ee989")
          end
        end

        context "int64 base64 encoding" do
          let(:config) { super().merge("base64encode" => true) }
          let(:data) { {"clientip" => 2148483647 } }

          it "fingerprints the value" do
            expect(fingerprint).to eq("/cdpmoJVbIxYQTHwEz7piQ==")
          end
        end
      end

      describe "the SHA1 method" do
        let(:fingerprint_method) { "SHA1" }

        it "fingerprints the value" do
          expect(fingerprint).to eq("3a5076c520b4b463f43806896ea0b3978d09dcae")
        end

        context "with HMAC" do
          let(:config) { super().merge("key" => "longencryptionkey") }

          it "fingerprints the value" do
            expect(fingerprint).to eq("fdc60acc4773dc5ac569ffb78fcb93c9630797f4")
          end
          context "with HMAC and base64 encoding" do
            let(:config) { super().merge("base64encode" => true) }
            it "fingerprints the value" do
              expect(fingerprint).to eq("/cYKzEdz3FrFaf+3j8uTyWMHl/Q=")
            end
          end
        end
        context "and base64 encoding" do
          let(:config) { super().merge("base64encode" => true) }
          it "fingerprints the value" do
            expect(fingerprint).to eq("OlB2xSC0tGP0OAaJbqCzl40J3K4=")
          end
        end
      end

      context "the SHA256 algorithm" do
        let(:fingerprint_method) { "SHA256" }
        it "fingerprints the value" do
          expect(fingerprint).to eq("4dabcab210766e35f03e77120e6986d6e6d4752b2a9ff22980b9253d026080d8")
        end
        context "with HMAC" do
          let(:config) { super().merge("key" => "longencryptionkey") }
          it "fingerprints the value" do
            expect(fingerprint).to eq("345bec3eff242d53b568916c2610b3e393d885d6b96d643f38494fd74bf4a9ca")
          end
          context "and base64 encoding" do
            let(:config) { super().merge("base64encode" => true) }
            it "fingerprints the value" do
              expect(fingerprint).to eq("NFvsPv8kLVO1aJFsJhCz45PYhda5bWQ/OElP10v0qco=")
            end
          end
        end
      end

      context "the SHA384 algorithm" do
        let(:fingerprint_method) { "SHA384" }
        it "fingerprints the value" do
          expect(fingerprint).to eq("fd605b0a3af3e04ce0d7a0b0d9c48d67a12dab811f60072e6eae84e35d567793ffb68a1807536f11c90874065c2a4392")
        end
        context "with HMAC" do
          let(:config) { super().merge("key" => "longencryptionkey") }
          it "fingerprints the value" do
            expect(fingerprint).to eq("22d4c0e8c4fbcdc4887d2038fca7650f0e2e0e2457ff41c06eb2a980dded6749561c814fe182aff93e2538d18593947a")
          end
          context "and base64 encoding" do
            let(:config) { super().merge("base64encode" => true) }
            it "fingerprints the value" do
              expect(fingerprint).to eq("ItTA6MT7zcSIfSA4/KdlDw4uDiRX/0HAbrKpgN3tZ0lWHIFP4YKv+T4lONGFk5R6")
            end
          end
        end
      end
      context "the SHA512 algorithm" do
        let(:fingerprint_method) { "SHA512" }
        it "fingerprints the value" do
          expect(fingerprint).to eq("5468e2dc64ea92b617782aae884b35af60041ac9e168a283615b6a462c54c13d42fa9542cce9b7d76a8124ac6616818905e3e5dd35d6e519f77c3b517558639a")
        end
        context "with HMAC" do
          let(:config) { super().merge("key" => "longencryptionkey") }
          it "fingerprints the value" do
            expect(fingerprint).to eq("11c19b326936c08d6c50a3c847d883e5a1362e6a64dd55201a25f2c1ac1b673f7d8bf15b8f112a4978276d573275e3b14166e17246f670c2a539401c5bfdace8")
          end
          context "and base64 encoding" do
            let(:config) { super().merge("base64encode" => true) }
            it "fingerprints the value" do
              expect(fingerprint).to eq("EcGbMmk2wI1sUKPIR9iD5aE2Lmpk3VUgGiXywawbZz99i/FbjxEqSXgnbVcydeOxQWbhckb2cMKlOUAcW/2s6A==")
            end
          end
        end
      end
      context "the MD5 algorithm" do
        let(:fingerprint_method) { "MD5" }
        it "fingerprints the value" do
          expect(fingerprint).to eq("ccdd8d3d940a01b2fb3258c059924c0d")
        end
        context "with HMAC" do
          let(:config) { super().merge("key" => "longencryptionkey") }
          it "fingerprints the value" do
            expect(fingerprint).to eq("9336c879e305c9604a3843fc3e75948f")
          end
          context "and base64 encoding" do
            let(:config) { super().merge("base64encode" => true) }
            it "fingerprints the value" do
              expect(fingerprint).to eq("kzbIeeMFyWBKOEP8PnWUjw==")
            end
          end
        end
      end
    end

    context "multiple values in the source field" do
      let(:config) { super().merge("source" => ["clientip" ]) }
      let(:data) { { "clientip" => [ "123.123.123.123", "223.223.223.223" ] } }

      it "produces a fingerprint array" do
        expect(fingerprint).to eq(["3a5076c520b4b463f43806896ea0b3978d09dcae", "47bbc4e06edebbace047fed35abeceec64968b81"])
      end
    end

    describe "concatenate_all_fields" do
      let(:config) { { "concatenate_all_fields" => true } }
      # The @timestamp field is specified in this sample event as we need the event contents to be constant for the tests
      let(:data) do
        { "@timestamp" => "2017-07-26T14:44:27.064Z", "clientip" => "123.123.123.123", "message" => "This is a test message", "log_level" => "INFO", "offset" => 123456789, "type" => "test" }
      end

      it "fingerprints the concatenated values" do
        expect(fingerprint).to eq("cbf022518e97860403160ed8a41847c0db104e63")
      end
    end

    context "when multiple fields are used" do
      let(:config) { super().merge("source" => ['field1', 'field2']) }
      let(:data) { { "field1" => "test1", "field2" => "test2" } }

      it "fingerprints the value of the last value" do
        # SHA1 of "test2"
        expect(fingerprint).to eq("109f4b3c50d7b0df729d299bc6f8e9ef9066971f")
      end

      describe "with concatenate_sources" do
        let(:config) { super().merge("concatenate_sources" => true) }
        it "fingerprints the value of concatenated key/pairs" do
          # SHA1 of "|field1|test1|field2|test2|"
          expect(fingerprint).to eq("e3b6b71eedc656f1d29408264e8a75535db985cb")
        end
      end
    end

    context "when utf-8 chars used" do
      let(:config) { super().merge("source" => ['field1', 'field2']) }
      let(:data) { {"field1"=>[{"inner_key"=>"🂡"}, {"1"=>"2"}], "field2"=>"🂡"} }
      it "fingerprints the value of the last value" do
        # SHA1 of "|field1|inner_key|🂡|1|2|field2|🂡|"
        expect(fingerprint).to eq("58fa9e0e60c9f0d24b51d84cddb26732a39eeb3d")
      end

      describe "with concatenate_sources" do
        let(:config) { super().merge("concatenate_sources" => true) }
        it "fingerprints the value of concatenated key/pairs" do
          # SHA1 of "|field1|inner_key|🂡|1|2|field2|🂡|"
          expect(fingerprint).to eq("d74f41841c7cdc793a97c218d2ff18064a5f1950")
        end
      end
    end

    describe "PUNCTUATION method" do
      let(:fingerprint_method) { 'PUNCTUATION' }
      let(:config) { super().merge("source" => 'field1') }
      let(:data) { { "field1" =>  "PHP Warning:  json_encode() [<a href='function.json-encode'>function.json-encode</a>]: Invalid UTF-8 sequence in argument in /var/www/htdocs/test.php on line 233" } }

      it "extracts punctiation as the fingerprint" do
        expect(fingerprint).to eq(":_()[<='.-'>.-</>]:-////.")
      end
    end

    context 'Timestamps' do
      let(:epoch_time) { Time.at(0).gmtime }
      let(:config) { super().merge("source" => ['@timestamp']) }

      describe 'OpenSSL Fingerprinting' do
        let(:config) { super().merge("key" => '0123') }
        let(:fingerprint_method) { "SHA1" }
        let(:data) { { "@timestamp" => epoch_time } }
        it "fingerprints the timestamp correctly" do
          # the string format of LogStash::Timestamp has breaking change in Logstash 8
          hash = lt_version_8? ? '1d5379ec92d86a67cfc642d55aa050ca312d3b9a' : '437291481f9b52199fcc6e3c6ea31ef4ad1c8fe5'
          expect(fingerprint).to eq(hash)
        end
      end

      describe 'MURMUR3 Fingerprinting' do
        let(:fingerprint_method) { "MURMUR3" }
        let(:data) { { "@timestamp" => epoch_time } }
        it "fingerprints the timestamp correctly" do
          hash = lt_version_8? ? 743372282 : 1154765817
          expect(fingerprint).to eq(hash)
        end
      end

      describe 'MURMUR3_128 Fingerprinting' do
        let(:fingerprint_method) { "MURMUR3_128" }
        let(:data) { { "@timestamp" => epoch_time } }
        it "fingerprints the timestamp correctly" do
          hash = lt_version_8? ? '37785b62a8cae473acc315d39b66d86e' : 'a0287bec80fce9eb6a1457efae3a7aeb'
          expect(fingerprint).to eq(hash)
        end
      end

      def lt_version_8?
        Gem::Version.new(LOGSTASH_VERSION) < Gem::Version.new('8.0.0')
      end
    end

    describe "post fingerprint execution triggers" do
      let(:fingerprint_method) { "PUNCTUATION" }
      let(:config) do
        {
          "source" => 'field1',
          "add_field" => { 'myfield' => 'myvalue' },
          "add_tag" => ['mytag']
        }
      end
      let(:data) { { "field1" => "Hello, World!" } }

      it "adds the new field" do
        expect(event.get("myfield")).to eq("myvalue")
      end
      it "adds the new tag" do
        expect(event.get("tags")).to include("mytag")
      end
    end

    describe "tolerance to hash order" do
      # insertion order can influence the result of to_hash's keys
      let(:data1) { {
        "a" => {"a0" => 0, "a1" => 1},
        "b" => {"b0" => 0, "b1" => 1},
      } }
      let(:event1) { LogStash::Event.new(data1) }
      let(:data2) { {
        "b" => {"b1" => 1, "b0" => 0},
        "a" => {"a1" => 1, "a0" => 0},
      } }
      let(:event2) { LogStash::Event.new(data2) }
      let(:config) { { "source" => [ "a" ] } }

      before(:each) do
        # for testing purposes we want to ensure the hash order is different.
        # since we can't easily control the order on the underlying Map,
        # we're mocking the order here:
        allow(event1).to receive(:to_hash).and_return(data1)
        allow(event2).to receive(:to_hash).and_return(data2)
        # by default event.get(key) fetches data from the event.
        # mocking the default value has to be done first, and only
        # then we can mock the getting "a" and "b"
        allow(event1).to receive(:get).and_call_original
        allow(event2).to receive(:get).and_call_original
        # mock event.get("a") and event.get("b") for both events
        # so we can inject an inconsistent order for the tests
        allow(event1).to receive(:get).with("a") {|arg| data1["a"] }
        allow(event1).to receive(:get).with("b") {|arg| data1["b"] }
        allow(event2).to receive(:get).with("a") {|arg| data2["a"] }
        allow(event2).to receive(:get).with("b") {|arg| data2["b"] }
        plugin.filter(event1)
        plugin.filter(event2)
      end
      it "computes the same hash" do
        # confirm the order of the keys in the nested hash is different
        # (of course it is, we just mocked the to_hash return)
        expect(event1.to_hash["a"].keys).to_not eq(event2.to_hash["a"].keys)
        # let's check that the fingerprint doesn't care about the insertion order
        expect(event1.get("fingerprint")).to eq(event2.get("fingerprint"))
      end
      context "concatenate_sources" do
        let("config") { { "source" => [ "a", "b"], "concatenate_sources" => true } }
        it "computes the same hash" do
          expect(event1.get("fingerprint")).to eq(event2.get("fingerprint"))
        end
      end
      context "concatenate_all_fields => true" do
        let(:config) { { "concatenate_all_fields" => true } }
        it "computes the same hash" do
          expect(event1.get("fingerprint")).to eq(event2.get("fingerprint"))
        end
      end
    end

  end
end
