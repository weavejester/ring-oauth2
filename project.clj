(defproject ring-oauth2 "0.1.1"
  :description "OAuth 2.0 client middleware for Ring"
  :url "https://github.com/weavejester/ring-oauth2"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.7.1"]
                 [clj-http "3.6.1"]
                 [clj-time "0.13.0"]
                 [ring/ring-core "1.6.2"]]
  :profiles
  {:dev {:dependencies [[clj-http-fake "1.0.3"]
                        [ring/ring-mock "0.3.1"]]}})
