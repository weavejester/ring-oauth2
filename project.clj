(defproject ring-oauth2 "0.3.0"
  :description "OAuth 2.0 client middleware for Ring"
  :url "https://github.com/weavejester/ring-oauth2"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [cheshire "5.13.0"]
                 [clj-http "3.13.0"]
                 [ring/ring-core "1.12.2"]]
  :profiles
  {:dev {:dependencies [[clj-http-fake "1.0.4"]
                        [ring/ring-mock "0.4.0"]]}})
