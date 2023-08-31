(defproject ring-oauth2 "0.2.0"
  :description "OAuth 2.0 client middleware for Ring"
  :url "https://github.com/weavejester/ring-oauth2"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.10.1"]
                 [clj-http "3.12.3"]
                 [ring/ring-core "1.9.4"]]
  :profiles
  {:dev {:dependencies [[clj-http-fake "1.0.3"]
                        [ring/ring-mock "0.4.0"]]}})
