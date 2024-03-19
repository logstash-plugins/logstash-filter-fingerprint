## 3.4.4
  - Fix, eagerly load OpenSSL classes ot avoid uninitialized constant error [#76](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/76)

## 3.4.3
  - pin murmurhash3 to 0.1.6 [#74](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/74)

## 3.4.2
  - Key config type changed to `Password` type for better protection from leaks. [#71](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/71)

## 3.4.1
  - Added backward compatibility of timestamp format to provide consistent fingerprint [#67](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/67)

## 3.4.0
  - Added support for 128bit murmur variant [#66](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/66).

## 3.3.2
  - [DOC] Clarify behavior when key is set [#65](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/65). 

## 3.3.1
  - Force encoding to UTF-8 when concatenating sources to generate fingerprint [#64](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/64)

## 3.3.0
  - Add ECS compatibility [#62](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/62)

## 3.2.4
  - Fixed the error in Murmur3 with Integer [#61](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/61)

## 3.2.3
  - [DOC] Expanded description for concatenate_sources behavior and provided examples [#60](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/60)

## 3.2.2
  - Fixed lack of consistent fingerprints on Hash/Map objects [#55](https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/55)

## 3.2.1
  - Fixed concurrent SHA fingerprinting by making the instances thread local

## 3.2.0
  - Added support for non-keyed, regular hash functions [#18](https://github.com/logstash-plugins/logstash-filter-fingerprint/issues/18)

## 3.1.2
  - Update gemspec summary

## 3.1.1
  - Fix some documentation issues

## 3.1.0
  - Add new setting `concatenate_all_fields`

## 3.0.4
  - Documentation improvements

## 3.0.3
  - improve documentation and register exception messaging

## 3.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.0.1
 - internal: Republish all the gems under jruby.

## 3.0.0
 - internal,deps: Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141

## 2.0.5
 - internal,deps: Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.4
 - internal,deps: New dependency requirements for logstash-core for the 5.0 release

## 2.0.3
 - internal,cleanup: Eager loading of libraries, optimizations and cleanups https://github.com/logstash-plugins/logstash-filter-fingerprint/pull/10

## 2.0.0
 - internal: Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - internal,deps: Dependency on logstash-core update to 2.0

