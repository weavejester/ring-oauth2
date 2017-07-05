(ns ring.middleware.oauth2
  (:require [clj-http.client :as http]
            [clj-time.core :as time]
            [clojure.string :as str]
            [crypto.random :as random]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp]))

(defn- redirect-uri [profile request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri profile))
      str))

(defn- scopes [profile]
  (str/join " " (map name (:scopes profile))))

(defn- authorize-uri [profile request state]
  (str (:authorize-uri profile) "?"
       (codec/form-encode {:response_type "code"
                           :client_id     (:client-id profile)
                           :redirect_uri  (redirect-uri profile request)
                           :scope         (scopes profile)
                           :state         state})))

(defn- random-state []
  (-> (random/base64 9) (str/replace "+" "-") (str/replace "/" "_")))

(defn- make-launch-handler [profile]
  (fn [{:keys [session] :or {session {}} :as request}]
    (let [state (random-state)]
      (-> (resp/redirect (authorize-uri profile request state))
          (assoc :session (assoc session ::state state))))))

(defn- state-matches? [request]
  (= (get-in request [:session ::state])
     (get-in request [:query-params "state"])))

(defn- format-access-token [{{:keys [access_token expires_in]} :body}]
  {:token   access_token
   :expires (-> expires_in time/seconds time/from-now)})

(defn- get-access-token [{:keys [access-token-uri client-id]} request]
  (format-access-token
   (http/post access-token-uri
              {:accept :json
               :as     :json
               :form-params {:grant_type   "authorization_code"
                             :code         (get-in request [:query-params "code"])
                             :redirect_uri (req/request-url request)
                             :client_id    client-id}})))

(def ^:private state-mismatch-response
  {:status 400, :headers {}, :body "State mismatch"})

(defn- make-redirect-handler [{:keys [id landing-uri] :as profile}]
  (fn [{:keys [session] :or {session {}} :as request}]
    (if (state-matches? request)
      (let [access-token (get-access-token profile request)]
        (-> (resp/redirect landing-uri)
            (assoc :session (-> session
                                (assoc-in [::access-tokens id] access-token)
                                (dissoc ::state)))))
      state-mismatch-response)))

(defn- assoc-access-tokens [request]
  (if-let [tokens (-> request :session ::access-tokens)]
    (assoc request :oauth2/access-tokens tokens)
    request))

(defn wrap-oauth2 [handler profiles]
  (let [profiles  (for [[k v] profiles] (assoc v :id k))
        launches  (into {} (map (juxt :launch-uri identity)) profiles)
        redirects (into {} (map (juxt :redirect-uri identity)) profiles)]
    (fn [{:keys [uri] :as request}]
      (if-let [profile (launches uri)]
        ((make-launch-handler profile) request)
        (if-let [profile (redirects uri)]
          ((make-redirect-handler profile) request)
          (handler (assoc-access-tokens request)))))))
