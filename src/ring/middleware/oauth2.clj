(ns ring.middleware.oauth2
  (:require [ring.middleware.oauth2.strategy :as csrf]
            [ring.middleware.oauth2.strategy.session :as session]
            [ring.middleware.oauth2.default-handlers :as default-handlers]
            [clj-http.client :as http]
            [clj-time.core :as time]
            [clojure.string :as str]
            [crypto.random :as random]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp]
            [clojure.tools.logging :as log]))


(defn- redirect-uri [profile request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri profile))
      str))

(defn- scopes [profile]
  (str/join " " (map name (:scopes profile))))

(defn- authorize-uri [profile request state]
  (str (:authorize-uri profile)
       (if (.contains ^String (:authorize-uri profile) "?") "&" "?")
       (codec/form-encode {:response_type "code"
                           :client_id     (:client-id profile)
                           :redirect_uri  (redirect-uri profile request)
                           :scope         (scopes profile)
                           :state         state})))

(defn- make-launch-handler [strategy profile]
  (fn [request]
    (let [token (csrf/get-token strategy request)
          response (resp/redirect (authorize-uri profile request token))]
      (csrf/write-token strategy profile request response token))))


(defn- format-access-token
  [{{:keys [access_token expires_in refresh_token id_token error error_description error_uri]} :body :as r}]
  (when error
    (log/warn (str error ": " error_description ", " error_uri) {:request r}))
  (cond-> {:token access_token}
          expires_in (assoc :expires (-> expires_in time/seconds time/from-now))
          refresh_token (assoc :refresh-token refresh_token)
          id_token (assoc :id-token id_token)))

(defn- request-params [profile request]
  {:grant_type   "authorization_code"
   :code         (get-in request [:query-params "code"])
   :redirect_uri (redirect-uri profile request)})

(defn- add-header-credentials [opts id secret]
  (assoc opts :basic-auth [id secret]))

(defn- add-form-credentials [opts id secret]
  (update-in
    opts
    [:form-params]
    merge
    {:client_id id, :client_secret secret}))

(defn- get-access-token
  [{:keys [access-token-uri client-id client-secret basic-auth?]
    :or   {basic-auth? false} :as profile} request]
  (format-access-token
    (http/post access-token-uri
               (cond-> {:accept      :json, :as :json,
                        :form-params (request-params profile request)}
                       basic-auth? (add-header-credentials client-id client-secret)
                       (not basic-auth?) (add-form-credentials client-id client-secret)))))

(defn- parse-redirect-url [{:keys [redirect-uri]}]
  (.getPath (java.net.URI. redirect-uri)))

(defn wrap-access-tokens [handler]
  (fn [request]
    (handler
      (if-let [tokens (-> request :session ::access-tokens)]
        (assoc request :ring.middleware.oauth2/access-tokens tokens)
        request))))


(defn wrap-access-token-response
  "if access-token-to-session? is true adds the access-token to the session for
  response"
  [{:keys [id landing-uri] :as profile}
   {:keys [session] :or {session {}} :as request}
   response
   access-token
   access-token-to-session?]
  (if access-token-to-session?
    (let [session (assoc-in session [:ring.middleware.oauth2/access-tokens id] access-token)]
      (assoc response :session session))
    response))

(defn- read-token [request]
  (get-in request [:query-params "state"]))

(defn- make-redirect-handler [strategy {:keys [id landing-uri] :as profile} access-token-to-session?]
  (let [error-handler (:state-mismatch-handler profile default-handlers/default-state-mismatch-handler)
        success-handler (:success-handler profile default-handlers/default-success-handler)]
    (fn [request]
      (if (csrf/valid-token? strategy profile request (read-token request))
        (let [access-token (get-access-token profile request)
              response (wrap-access-token-response profile
                                                   request
                                                   (success-handler profile access-token request)
                                                   access-token
                                                   access-token-to-session?)]
          (csrf/remove-token strategy profile response))
        (error-handler profile request)))))

(defn wrap-oauth2-flow [handler profiles & {:keys [strategy access-token-to-session?]
                                            :or   {strategy                 (session/session-strategy)
                                                   access-token-to-session? true}}]
  (let [profiles (for [[k v] profiles] (assoc v :id k))
        launches (into {} (map (juxt :launch-uri identity)) profiles)
        redirects (into {} (map (juxt parse-redirect-url identity)) profiles)]
    (fn [{:keys [uri] :as request}]
      (if-let [profile (launches uri)]
        ((make-launch-handler strategy profile) request)
        (if-let [profile (redirects uri)]
          ((make-redirect-handler strategy profile access-token-to-session?) request)
          (handler request))))))


(defn wrap-oauth2 [handler profiles & options]
  (->
    (apply wrap-oauth2-flow handler profiles options)
    (wrap-access-tokens)))
