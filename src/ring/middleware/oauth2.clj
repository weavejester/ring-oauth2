(ns ring.middleware.oauth2)

(defn wrap-oauth2 [handler]
  (fn [request]
    (handler request)))
