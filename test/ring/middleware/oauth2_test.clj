(ns ring.middleware.oauth2-test
  (:require [clj-http.fake :as fake]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cheshire.core :as cheshire]
            [ring.middleware.oauth2 :as oauth2 :refer [wrap-oauth2]]
            [ring.mock.request :as mock]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.codec :as codec])
  (:import [java.time Instant]
           [java.util Date]))

(def test-profile
  {:authorize-uri    "https://example.com/oauth2/authorize"
   :access-token-uri "https://example.com/oauth2/access-token"
   :redirect-uri     "/oauth2/test/callback"
   :launch-uri       "/oauth2/test"
   :landing-uri      "/"
   :scopes           [:user :project]
   :client-id        "abcdef"
   :client-secret    "01234567890abcdef"})

(def test-profile-pkce
  (assoc test-profile :pkce? true))

(defn- token-handler
  ([{:keys [oauth2/access-tokens]}]
   {:status 200, :headers {}, :body access-tokens})
  ([request respond _raise]
   (respond (token-handler request))))

(def test-handler
  (wrap-oauth2 token-handler {:test test-profile}))

(def test-handler-pkce
  (wrap-oauth2 token-handler {:test test-profile-pkce}))

(deftest test-launch-uri
  (testing "sync handlers"
    (let [response  (test-handler (mock/request :get "/oauth2/test"))
          location  (get-in response [:headers "Location"])
          [_ query] (str/split location #"\?" 2)
          params    (codec/form-decode query)]
      (is (= 302 (:status response)))
      (is (.startsWith ^String location "https://example.com/oauth2/authorize?"))
      (is (= {"response_type" "code"
              "client_id"     "abcdef"
              "redirect_uri"  "http://localhost/oauth2/test/callback"
              "scope"         "user project"}
             (dissoc params "state")))
      (is (re-matches #"[A-Za-z0-9_-]{12}" (params "state")))
      (is (= {::oauth2/state (params "state")}
             (:session response)))))

  (testing "async handlers"
    (let [respond (promise)
          raise   (promise)]
      (test-handler (mock/request :get "/oauth2/test") respond raise)
      (let [response  (deref respond 100 :empty)
            error     (deref raise 100 :empty)]
        (is (not= response :empty))
        (is (= error :empty))
        (let [location  (get-in response [:headers "Location"])
              [_ query] (str/split location #"\?" 2)
              params    (codec/form-decode query)]
          (is (= 302 (:status response)))
          (is (.startsWith ^String location "https://example.com/oauth2/authorize?"))
          (is (= {"response_type" "code"
                  "client_id"     "abcdef"
                  "redirect_uri"  "http://localhost/oauth2/test/callback"
                  "scope"         "user project"}
                 (dissoc params "state")))
          (is (re-matches #"[A-Za-z0-9_-]{12}" (params "state")))
          (is (= {::oauth2/state (params "state")}
                 (:session response))))))))

(deftest test-launch-uri-pkce
  (let [response  (test-handler-pkce (mock/request :get "/oauth2/test"))
        location  (get-in response [:headers "Location"])
        [_ query] (str/split location #"\?" 2)
        params    (codec/form-decode query)]
    (is (contains? params "code_challenge"))
    (is (= "S256" (get params "code_challenge_method")))))

(deftest test-missing-fields
  (let [profile (assoc test-profile :client-id nil)]
    (is (thrown? AssertionError (wrap-oauth2 token-handler {:test profile}))))

  (let [profile (assoc test-profile :client-secret nil)]
    (is (thrown? AssertionError (wrap-oauth2 token-handler {:test profile})))))

(deftest test-location-uri-with-query
  (let [profile  (assoc test-profile
                        :authorize-uri
                        "https://example.com/oauth2/authorize?pid=XXXX")
        handler   (wrap-oauth2 token-handler {:test profile})
        response  (handler (mock/request :get "/oauth2/test"))
        location  (get-in response [:headers "Location"])]
    (is (.startsWith ^String location
                     "https://example.com/oauth2/authorize?pid=XXXX&"))))

(def token-response
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body "{\"access_token\":\"defdef\",\"expires_in\":3600,\"foo\":\"bar\"}"})

(defn- approx-eq [a b]
  (let [a-ms (.getTime a)
        b-ms (.getTime b)]
    (< (- a-ms 1000) b-ms (+ a-ms 1000))))

(defn- seconds-from-now-to-date [secs]
  (-> (Instant/now) (.plusSeconds secs) (Date/from)))

(deftest test-redirect-uri
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly token-response)}

    (testing "valid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (test-handler request)
            expires  (seconds-from-now-to-date 3600)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef"
               (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq expires
                       (-> response
                           :session ::oauth2/access-tokens :test :expires)))
        (is (= {:foo "bar"}
               (-> response
                   :session ::oauth2/access-tokens :test :extra-data)))))

    (testing "invalid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxya"}))
            response (test-handler request)]
        (is (= {:status  400
                :headers {"Content-Type" "text/plain; charset=utf-8"}
                :body    "OAuth2 error: state mismatch"}
               response))))

    (testing "custom state mismatched error"
      (let [error    {:status 400, :headers {}, :body "Error!"}
            profile  (assoc test-profile
                            :state-mismatch-handler (constantly error))
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxya"}))
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))

    (testing "no authorization code"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"state" "xyzxyz"}))
            response (test-handler request)]
        (is (= {:status  400
                :headers {"Content-Type" "text/plain; charset=utf-8"}
                :body    "OAuth2 error: no authorization code"}
               response))))

    (testing "custom no authorization code error"
      (let [error    {:status 400, :headers {}, :body "Error!"}
            profile  (assoc test-profile
                            :no-auth-code-handler (constantly error))
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"state" "xyzxyz"}))
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))

    (testing "absolute redirect uri"
      (let [profile  (assoc test-profile
                            :redirect-uri
                            "https://example.com/oauth2/test/callback?query")
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (handler request)
            expires  (seconds-from-now-to-date 3600)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef"
               (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq expires
                       (-> response
                           :session ::oauth2/access-tokens :test :expires)))))))

(deftest test-access-tokens-key
  (let [tokens {:test {:token "defdef", :expires 3600}}]
    (is (= {:status 200, :headers {}, :body tokens}
           (-> (mock/request :get "/")
               (assoc :session {::oauth2/access-tokens tokens})
               (test-handler))))))

(deftest test-true-basic-auth-param
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
      (fn [req]
        (let [auth (get-in req [:headers "authorization"])]
          (is (and (not (str/blank? auth))
                   (.startsWith auth "Basic")))
          token-response))}

    (testing "valid state"
      (let [profile  (assoc test-profile :basic-auth? true)
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (handler request)]
        (is (= 302 (:status response)))))))

(defn- contains-many? [m & ks]
  (every? #(contains? m %) ks))

(deftest test-false-basic-auth-param
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (wrap-params (fn [req]
                     (let [params (get-in req [:params])]
                        (is (contains-many? params "client_id" "client_secret"))
                       token-response)))}

    (testing "valid state"
      (let [profile  (assoc test-profile :basic-auth? false)
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (handler request)]
        (is (= 302 (:status response)))))))

(def openid-response
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600,
              \"refresh_token\":\"ghighi\",\"id_token\":\"abc.def.ghi\"}"})

(deftest test-openid-response
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly openid-response)}

    (testing "valid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (test-handler request)
            expires  (seconds-from-now-to-date 3600)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef"
               (-> response :session ::oauth2/access-tokens :test :token)))
        (is (= "ghighi"
               (-> response
                   :session ::oauth2/access-tokens :test :refresh-token)))
        (is (= "abc.def.ghi"
               (-> response
                   :session ::oauth2/access-tokens :test :id-token)))
        (is (approx-eq expires
                       (-> response
                           :session ::oauth2/access-tokens :test :expires)))))

    (testing "async handler"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            respond  (promise)
            raise    (promise)
            expires  (seconds-from-now-to-date 3600)]
        (test-handler request respond raise)
        (let [response (deref respond 100 :empty)
              error    (deref raise 100 :empty)]
          (is (not= response :empty) "timeout getting response")
          (is (= error :empty))
          (is (= 302 (:status response)))
          (is (= "/" (get-in response [:headers "Location"])))
          (is (map? (-> response :session ::oauth2/access-tokens)))
          (is (= "defdef"
                 (-> response :session ::oauth2/access-tokens :test :token)))
          (is (= "ghighi"
                 (-> response
                     :session ::oauth2/access-tokens :test :refresh-token)))
          (is (= "abc.def.ghi"
                 (-> response
                     :session ::oauth2/access-tokens :test :id-token)))
          (is (approx-eq expires
                         (-> response
                             :session ::oauth2/access-tokens :test :expires))))))))

(def openid-response-with-string-expires
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\": \"3600\",
              \"refresh_token\":\"ghighi\",\"id_token\":\"abc.def.ghi\"}"})

(deftest test-openid-response-with-string-expires
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (constantly openid-response-with-string-expires)}

    (testing "valid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (test-handler request)
            expires  (seconds-from-now-to-date 3600)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (approx-eq expires
                       (-> response
                           :session ::oauth2/access-tokens :test :expires)))))))

(defn openid-response-with-code-verifier [req]
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    (cheshire/generate-string
             {:access_token "defdef"
              :expires_in 3600
              :refresh_token "ghighi"
              :id_token "abc.def.ghi"
              :code_verifier (-> req :body slurp codec/form-decode
                                 (get "code_verifier"))})})

(deftest test-openid-response-with-code-verifier
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     openid-response-with-code-verifier}

    (testing "verifier in extra data"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"
                                          ::oauth2/code-verifier "jkljkl"})
                         (assoc :query-params {"code"  "abcabc"
                                               "state" "xyzxyz"}))
            response (test-handler-pkce request)]
        (is (= "jkljkl"
               (-> response
                   :session ::oauth2/access-tokens :test
                   :extra-data :code_verifier)))))))

(defn- redirect-handler [_]
  {:status 200, :headers {}, :body "redirect-handler-response-body"})

(deftest test-redirect-handler
  (let [profile  (assoc test-profile
                        :redirect-handler redirect-handler)
        handler  (wrap-oauth2 token-handler {:test profile})
        request  (-> (mock/request :get "/oauth2/test/callback")
                     (assoc :session {::oauth2/state "xyzxyz"})
                     (assoc :query-params {"code" "abcabc", "state" "xyzxyz"}))
        response (handler request)
        body     (:body response)]
    (is (= "redirect-handler-response-body" body))))

(deftest test-handler-passthrough
  (let [tokens  {:test "tttkkkk"}
        request (-> (mock/request :get "/example")
                    (assoc :session {::oauth2/access-tokens tokens}))]
    (testing "sync handler"
      (is (= {:status 200, :headers {}, :body tokens}
             (test-handler request))))

    (testing "async handler"
      (let [respond (promise)
            raise   (promise)]
        (test-handler request respond raise)
        (is (= :empty
               (deref raise 100 :empty)))
        (is (= {:status 200, :headers {}, :body tokens}
               (deref respond 100 :empty)))))))
