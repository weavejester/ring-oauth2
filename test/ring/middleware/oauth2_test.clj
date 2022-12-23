(ns ring.middleware.oauth2-test
  (:require [clj-http.fake :as fake]
            [clj-time.core :as time]
            [clojure.string :as str]
            [clojure.test :refer :all]
            [ring.middleware.oauth2 :as oauth2 :refer [wrap-oauth2]]
            [ring.mock.request :as mock]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.codec :as codec]))

(def test-profile
  {:authorize-uri    "https://example.com/oauth2/authorize"
   :access-token-uri "https://example.com/oauth2/access-token"
   :redirect-uri     "/oauth2/test/callback"
   :launch-uri       "/oauth2/test"
   :landing-uri      "/"
   :scopes           [:user :project]
   :client-id        "abcdef"
   :client-secret    "01234567890abcdef"})

(defn token-handler [{:keys [oauth2/access-tokens]}]
  {:status 200, :headers {}, :body access-tokens})

(def test-handler
  (wrap-oauth2 token-handler {:test test-profile}))

(deftest test-launch-uri
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

(deftest test-missing-fields
  (let [profile (assoc test-profile :client-id nil)]
    (is (thrown? AssertionError (wrap-oauth2 token-handler {:test profile}))))

  (let [profile (assoc test-profile :client-secret nil)]
    (is (thrown? AssertionError (wrap-oauth2 token-handler {:test profile})))))

(deftest test-location-uri-with-query
  (let [profile  (assoc test-profile
                        :authorize-uri
                        "https://example.com/oauth2/authorize?business_partner_id=XXXX")
        handler   (wrap-oauth2 token-handler {:test profile})
        response  (handler (mock/request :get "/oauth2/test"))
        location  (get-in response [:headers "Location"])]
    (is (.startsWith ^String location "https://example.com/oauth2/authorize?business_partner_id=XXXX&"))))

(def token-response
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600,\"foo\":\"bar\"}"})



(defn approx-eq [a b]
  (let [a-ms (.getTime a)
        b-ms (.getTime b)]
    (< (- a-ms 1000) b-ms (+ a-ms 1000))))


(deftest test-redirect-uri
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly token-response)}

    (testing "valid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxyz"}))
            response (test-handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq (oauth2/seconds-from-now-to-date 3600)
                       (-> response :session ::oauth2/access-tokens :test :expires)))
        (is (= {:foo "bar"} (-> response :session ::oauth2/access-tokens :test :extra-data)))))

    (testing "invalid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxya"}))
            response (test-handler request)]
        (is (= {:status 400, :headers {}, :body "State mismatch"}
               response))))

    (testing "custom state mismatched error"
      (let [error    {:status 400, :headers {}, :body "Error!"}
            profile  (assoc test-profile :state-mismatch-handler (constantly error))
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxya"}))
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))

    (testing "no authorization code"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"state" "xyzxyz"}))
            response (test-handler request)]
        (is (= {:status 400, :headers {}, :body "No authorization code"}
               response))))

    (testing "custom no authorization code error"
      (let [error    {:status 400, :headers {}, :body "Error!"}
            profile  (assoc test-profile :no-auth-code-handler (constantly error))
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
                         (assoc :query-params {"code" "abcabc", "state" "xyzxyz"}))
            response (handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq (oauth2/seconds-from-now-to-date 3600)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))))

(deftest test-access-tokens-key
  (let [tokens {:test {:token "defdef", :expires 3600}}]
    (is (= {:status 200, :headers {}, :body tokens}
           (test-handler (-> (mock/request :get "/")
                             (assoc :session {::oauth2/access-tokens tokens})))))))

(deftest test-true-basic-auth-param
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
      (fn [req]
          (let [auth (get-in req [:headers "authorization"])]
              (is (and (not (str/blank? auth))
                       (.startsWith auth "Basic")))
            token-response))}

    (testing "valid state"
      (let [profile (assoc test-profile :basic-auth? true)
            handler (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc"
                                               "state" "xyzxyz"}))
            response (handler request)]))))

(defn contains-many? [m & ks]
  (every? #(contains? m %) ks))

(deftest test-false-basic-auth-param
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (wrap-params (fn [req]
                     (let [params (get-in req [:params])]
                        (is (contains-many? params "client_id" "client_secret"))
                       token-response)))}

    (testing "valid state"
      (let [profile (assoc test-profile :basic-auth? false)
            handler (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxyz"}))
            response (handler request)]))))


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
                         (assoc :query-params {"code" "abcabc", "state" "xyzxyz"}))
            response (test-handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (= "ghighi" (-> response :session ::oauth2/access-tokens
                                              :test :refresh-token)))
        (is (= "abc.def.ghi" (-> response :session ::oauth2/access-tokens
                                                   :test :id-token)))
        (is (approx-eq (oauth2/seconds-from-now-to-date 3600)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))))

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
                         (assoc :query-params {"code" "abcabc" "state" "xyzxyz"}))
            response (test-handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (approx-eq (oauth2/seconds-from-now-to-date 3600)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))))

(defn redirect-handler [{:keys [oauth2/access-tokens]}]
  {:status 200, :headers {}, :body "redirect-handler-response-body"})

(deftest test-redirect-handler
  (let [profile  (assoc test-profile
                        :redirect-handler redirect-handler)
        handler  (wrap-oauth2 token-handler {:test profile})
        request  (-> (mock/request :get "/oauth2/test/callback")
                     (assoc :session {::oauth2/state "xyzxyz"})
                     (assoc :query-params {"code" "abcabc" "state" "xyzxyz"}))
        response (handler request)
        body     (:body response)]
    (is (= "redirect-handler-response-body" body))))
