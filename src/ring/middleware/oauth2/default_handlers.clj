(ns ring.middleware.oauth2.default-handlers
  (:require [ring.util.response :as resp]))

(defn default-success-handler
  [{:keys [id landing-uri] :as profile} access-token request]
  (resp/redirect landing-uri))



(defn default-state-mismatch-handler [_ _]
  {:status 400, :headers {}, :body "State mismatch"})