(ns ring.middleware.oauth2-test
  (:require [clj-http.fake :as fake]
            [clj-time.core :as time]
            [clojure.string :as str]
            [clojure.test :refer :all]
            [ring.middleware.oauth2 :as oauth2 :refer [wrap-oauth2]]
            [ring.mock.request :as mock]
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
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600}"})

(defn approx-eq [a b]
  (time/within?
   (time/interval (time/minus a (time/seconds 1)) (time/plus a (time/seconds 1)))
   b))

(deftest test-redirect-uri
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly token-response)}

    (testing "valid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxyz"}))
            response (test-handler request)
            expires  (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq (-> 3600 time/seconds time/from-now)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))

    (testing "invalid state"
      (let [request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxya"}))
            response (test-handler request)]
        (is (= {:status 400, :headers {}, :body "State mismatch"}
               response))))

    (testing "custom error"
      (let [error    {:status 400, :headers {}, :body "Error!"}
            profile  (assoc test-profile :state-mismatch-handler (constantly error))
            handler  (wrap-oauth2 token-handler {:test profile})
            request  (-> (mock/request :get "/oauth2/test/callback")
                         (assoc :session {::oauth2/state "xyzxyz"})
                         (assoc :query-params {"code" "abcabc", "state" "xyzxya"}))
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))))

(deftest test-access-tokens-key
  (let [tokens {:test {:token "defdef", :expires 3600}}]
    (is (= {:status 200, :headers {}, :body tokens}
           (test-handler (-> (mock/request :get "/")
                             (assoc :session {::oauth2/access-tokens tokens})))))))
