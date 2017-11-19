(defproject ring-oauth2 "0.1.4"
  :description "OAuth 2.0 client middleware for Ring"
  :url "https://github.com/weavejester/ring-oauth2"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.8.0"]
                 [clj-http "3.7.0"]
                 [clj-time "0.14.0"]
                 [ring/ring-core "1.6.3"]]
  :profiles
  {:dev {:dependencies [[clj-http-fake "1.0.3"]
                        [ring/ring-mock "0.3.1"]]}})
