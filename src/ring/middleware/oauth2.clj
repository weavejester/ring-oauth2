(ns ring.middleware.oauth2
  (:require [clj-http.client :as http]
            [clojure.string :as str]
            [crypto.random :as random]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp])
  (:import [java.time Instant]
           [java.util Date]))

(defn- redirect-uri [profile request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri profile))
      str))

(defn- scopes [profile]
  (str/join " " (map name (:scopes profile))))

(defn- authorize-uri [profile request state]
  (let [auth-uri (if (string? (:authorize-uri profile))
                   (:authorize-uri profile)
                   ((:authorize-uri profile) profile request))]
    (str auth-uri
         (if (.contains ^String auth-uri "?") "&" "?")
         (codec/form-encode {:response_type "code"
                             :client_id     (:client-id profile)
                             :redirect_uri  (redirect-uri profile request)
                             :scope         (scopes profile)
                             :state         state}))))

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

(defn- coerce-to-int [n]
  (if (string? n)
    (Integer/parseInt n)
    n))

(defn- format-access-token
  [{{:keys [access_token expires_in refresh_token id_token] :as body} :body}]
  (-> {:token access_token
       :extra-data (dissoc body :access_token :expires_in :refresh_token :id_token)}
      (cond-> expires_in (assoc :expires (-> (Instant/now)
                                             (.plusSeconds (coerce-to-int expires_in))
                                             (Date/from)))
              refresh_token (assoc :refresh-token refresh_token)
              id_token (assoc :id-token id_token))))

(defn- get-authorization-code [request]
  (get-in request [:query-params "code"]))

(defn- request-params [profile request]
  {:grant_type    "authorization_code"
   :code          (get-authorization-code request)
   :redirect_uri  (redirect-uri profile request)})

(defn- add-header-credentials [opts id secret]
  (assoc opts :basic-auth [id secret]))

(defn- add-form-credentials [opts id secret]
  (assoc opts :form-params (-> (:form-params opts)
                               (merge {:client_id     id
                                       :client_secret secret}))))

(defn- get-access-token
  [{:keys [access-token-uri client-id client-secret basic-auth?]
    :or {basic-auth? false} :as profile} request]
  (format-access-token
   (http/post
    (if (string? access-token-uri)
      access-token-uri
      (access-token-uri profile request))
    (cond-> {:accept :json, :as  :json,
             :form-params (request-params profile request)}
      basic-auth? (add-header-credentials client-id client-secret)
      (not basic-auth?) (add-form-credentials client-id client-secret)))))

(defn state-mismatch-handler [_]
  {:status 400, :headers {}, :body "State mismatch"})

(defn no-auth-code-handler [_]
  {:status 400, :headers {}, :body "No authorization code"})

(defn- make-redirect-handler [{:keys [id landing-uri] :as profile}]
  (let [state-mismatch-handler (:state-mismatch-handler
                                 profile state-mismatch-handler)
        no-auth-code-handler   (:no-auth-code-handler
                                 profile no-auth-code-handler)]
    (fn [{:keys [session] :or {session {}} :as request}]
      (cond
        (not (state-matches? request))
        (state-mismatch-handler request)

        (nil? (get-authorization-code request))
        (no-auth-code-handler request)

        :else
        (let [access-token (get-access-token profile request)]
          (-> (resp/redirect landing-uri)
              (assoc :session (-> session
                                  (assoc-in [::access-tokens id] access-token)
                                  (dissoc ::state)))))))))

(defn- assoc-access-tokens [request]
  (if-let [tokens (-> request :session ::access-tokens)]
    (assoc request :oauth2/access-tokens tokens)
    request))

(defn- parse-redirect-url [{:keys [redirect-uri]}]
  (.getPath (java.net.URI. redirect-uri)))

(defn- valid-profile? [{:keys [client-id client-secret] :as profile}]
  (and (some? client-id) (some? client-secret)))

(defn wrap-oauth2 [handler profiles]
  {:pre [(every? valid-profile? (vals profiles))]}
  (let [profiles  (for [[k v] profiles] (assoc v :id k))
        launches  (into {} (map (juxt :launch-uri identity)) profiles)
        redirects (into {} (map (juxt parse-redirect-url identity)) profiles)]
    (fn [{:keys [uri] :as request}]
      (if-let [profile (launches uri)]
        ((make-launch-handler profile) request)
        (if-let [profile (redirects uri)]
          ((:redirect-handler profile (make-redirect-handler profile)) request)
          (handler (assoc-access-tokens request)))))))
