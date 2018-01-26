(ns ring.middleware.oauth2.strategy.session
  (:require [ring.middleware.oauth2.strategy :as strategy]
            [ring.util.response :as resp]
            [clojure.string :as str]
            [crypto.random :as random]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Managing state using sessions
;;
;; This requires a session (or a shared session, can easily be distributed horizontally








#_(defn access-token-to-session
    [{:keys [id landing-uri] :as profile}
     access-token
     {:keys [session] :or {session {}} :as request}]
    (-> (default-success-handler profile access-token request)
        (assoc :session (-> session
                            (assoc-in [:ring.middleware.oauth2/access-tokens id] access-token)))))




(deftype SessionStrategy []
  strategy/Strategy

  (get-token [_ _]
    (-> (random/base64 9) (str/replace "+" "-") (str/replace "/" "_")))

  (write-token [strategy profile {:keys [session] :or {session {}} :as request} response token]
    (assoc response :session (assoc session :ring.middleware.oauth2/state token)))

  (remove-token [strategy profile response]
    (update-in response [:session] dissoc :ring.middleware.oauth2/state))

  (valid-token? [strategy profile request token]
    (= (get-in request [:session :ring.middleware.oauth2/state])
       token)))


(defn session-strategy []
  (->SessionStrategy))