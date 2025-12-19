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

(defn- seconds-from-now-to-date
  ([now secs] (-> now (.plusSeconds secs) (Date/from)))
  ([secs] (seconds-from-now-to-date (Instant/now) secs)))

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

(def refresh-token-response
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body "{\"access_token\":\"newtoken\",\"expires_in\":3600,
           \"refresh_token\":\"newrefresh\",\"foo\":\"bar\"}"})

(deftest test-token-refresh-success
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (fn [req]
       (let [params (codec/form-decode (slurp (:body req)))]
         (is (= "refresh_token" (get params "grant_type")))
         (is (= "oldrefresh" (get params "refresh_token")))
         refresh-token-response))}

    (let [now (Instant/now)
          old-expires  (seconds-from-now-to-date now -60)
          new-expires  (seconds-from-now-to-date now 3600)
          new-token    {:token "newtoken"
                        :refresh-token "newrefresh"
                        :extra-data {:foo "bar"}}
          request      (-> (mock/request :get "/")
                           (assoc :session
                                  {::oauth2/access-tokens
                                   {:test {:token "oldtoken"
                                           :refresh-token "oldrefresh"
                                           :expires old-expires}}}))]
      (testing "sync refresh"
        (let [response (test-handler request)]
          (is (= 200 (:status response)))
          ;; then handler has new token
          (is (= new-token (dissoc (get-in response [:body :test]) :expires)))
          (is (approx-eq new-expires (get-in response [:body :test :expires])))
          ;; and the user's session is updated
          (is (= new-token
                 (dissoc (get-in response
                                 [:session ::oauth2/access-tokens :test])
                         :expires)))))
      (testing "async refresh"
        (let [respond (promise)
              raise   (promise)]
          (test-handler request respond raise)
          (is (= :empty (deref raise 100 :empty)))
          (let [response (deref respond 100 :empty)]
            ;; then handler has new token
            (is (not= response :empty))
            (is (= new-token (dissoc (get-in response [:body :test]) :expires)))
            ;; user session is updated
            (is (= new-token
                   (dissoc (get-in response [:session ::oauth2/access-tokens
                                             :test])
                           :expires)))))))))

(def refresh-token-error-response
  {:headers {"content-type" "application/json"},
   :status 400,
   :body "{\"error\": \"invalid_grant\"}"})

(deftest test-token-refresh-failure
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (constantly refresh-token-error-response)}

    ;; setup a session with two grants, where one grant is expired and which
    ;; will error on refresh
    (let [profiles      {:test-0 test-profile :test-1 test-profile}
          handler       (wrap-oauth2 token-handler profiles)
          good-grant    {:token "good-token"
                         :refresh-token "refresh-token"
                         :expires (seconds-from-now-to-date 3600)}
          expired-grant {:token "expired-token"
                         :refresh-token "invalid"
                         :expires (seconds-from-now-to-date -60)}
          request       (-> (mock/request :get "/")
                            (assoc :session
                                   {::oauth2/access-tokens
                                    {:test-0 expired-grant
                                     :test-1 good-grant}}))]
      (testing "sync handler"
        (let [response (handler request)]
          (is (= {:test-1 good-grant}
                 (:body response)))))
      (testing "async refresh"
        (let [respond (promise)
              raise   (promise)]
          (handler request respond raise)
          (is (= :empty (deref raise 100 :empty)))
          (let [response (deref respond 100 :empty)]
            (is (not= response :empty))
            (is (= {:test-1 good-grant} (:body response)))))))))

(deftest test-token-refresh-clear-session
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (constantly refresh-token-response)}

    (let [clear-response {:status 200 :headers {} :body nil :session nil}
          session-clear-handler (fn
                                  ([_request] clear-response)
                                  ([_request respond _raise]
                                   (respond clear-response)))
          handler (wrap-oauth2 session-clear-handler {:test test-profile})
          now (Instant/now)
          old-expires (seconds-from-now-to-date now -60)
          request (-> (mock/request :get "/")
                      (assoc :session
                             {::oauth2/access-tokens
                              {:test {:token "oldtoken"
                                      :refresh-token "oldrefresh"
                                      :expires old-expires}}}))]

      (testing "sync handler"
        (let [response (handler request)]
          (is (= 200 (:status response)))
          (is (nil? (:session response)))))

      (testing "async handler"
        (let [respond (promise)
              raise (promise)]
          (handler request respond raise)
          (let [response (deref respond 100 :empty)
                error (deref raise 100 :empty)]
            (is (not= :empty response))
            (is (= :empty error))
            (is (= 200 (:status response)))
            (is (nil? (:session response)))))))))

(deftest test-token-refresh-preserves-session-state
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (constantly refresh-token-response)}

    (let [now (Instant/now)
          old-expires (seconds-from-now-to-date now -60)
          request (-> (mock/request :get "/")
                      (assoc :session
                             {:user-id 123  ; extra session state
                              ::oauth2/access-tokens
                              {:test {:token "oldtoken"
                                      :refresh-token "oldrefresh"
                                      :expires old-expires}}}))]

      (testing "handler sets new session state during refresh"
        (let [handler (wrap-oauth2
                       (fn
                         ([_] {:status 200 :body "ok"
                               :session {:user-id 123 :cart-items 5}})
                         ([_ respond _] (respond {:status 200 :body "ok"
                                                   :session {:user-id 123
                                                             :cart-items 5}})))
                       {:test test-profile})
              response (handler request)]
          ;; Handler's session changes preserved
          (is (= 5 (get-in response [:session :cart-items])))
          ;; Refreshed token added to handler's session
          (is (= "newtoken" (get-in response [:session ::oauth2/access-tokens
                                              :test :token])))))

      (testing "handler doesn't change session, extra state preserved"
        (let [handler (wrap-oauth2
                       (fn
                         ([_] {:status 200 :body "ok"})
                         ([_ respond _] (respond {:status 200 :body "ok"})))
                       {:test test-profile})
              response (handler request)]
          ;; Original session's extra state preserved
          (is (= 123 (get-in response [:session :user-id])))
          ;; Token refreshed
          (is (= "newtoken" (get-in response [:session ::oauth2/access-tokens
                                              :test :token]))))))))
