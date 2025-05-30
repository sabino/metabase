(ns metabase.search.test-util
  (:require
   [metabase.api.common :as api]
   [metabase.permissions.util :as perms-util]
   [metabase.request.core :as request] ;; For now, this is specialized to the appdb engine, but we should be able to generalize it to all engines.
   [metabase.search.appdb.index :as search.index]
   [metabase.search.config :as search.config]
   [metabase.search.core :as search]
   [metabase.search.engine :as search.engine]
   [metabase.search.impl :as search.impl]
   [metabase.test :as mt]
   [toucan2.core :as t2]))

(def ^:dynamic *user-ctx* nil)

#_{:clj-kondo/ignore [:metabase/test-helpers-use-non-thread-safe-functions]}
(defmacro with-sync-search-indexing
  "Perform all search indexing synchronously."
  [& body]
  `(binding [metabase.search.ingestion/*force-sync* true]
     ~@body))

#_{:clj-kondo/ignore [:metabase/test-helpers-use-non-thread-safe-functions]}
(defmacro with-temp-index-table
  "Create a temporary index table for the duration of the body."
  [& body]
  `(when (search/supports-index?)
     (search.index/with-temp-index-table
      ;; We need ingestion to happen on the same thread so that it uses the right search index.
       (with-sync-search-indexing
         ~@body))))

#_{:clj-kondo/ignore [:metabase/test-helpers-use-non-thread-safe-functions]}
(defmacro with-new-search-if-available
  "Create a temporary index table for the duration of the body."
  [& body]
  `(if (search/supports-index?)
     (mt/with-dynamic-fn-redefs [search.impl/default-engine (constantly :search.engine/appdb)]
       (with-temp-index-table
         (search/reindex!)
         ~@body))
     ~@body))

(defmacro with-legacy-search
  "Ensure legacy search, which doesn't require an index, is used."
  [& body]
  `(mt/with-dynamic-fn-redefs [search.impl/default-engine (constantly :search.engine/in-place)]
     ~@body))

(defmacro with-index-disabled
  "Skip any index maintenance during this test."
  [& body]
  `(mt/with-dynamic-fn-redefs [search.engine/active-engines (constantly nil)]
     ~@body))

(defmacro with-api-user [raw-ctx & body]
  `(let [raw-ctx# ~raw-ctx]
     (if-let [user-id# (:current-user-id raw-ctx#)]
       ;; for brevity in some tests, we don't require that the user really exists
       (if (t2/exists? :model/User user-id#)
         (request/with-current-user user-id# ~@body)
         (binding [*user-ctx* (merge {:current-user-id       user-id#
                                      :current-user-perms    #{"/"}
                                      :is-superuser?         true
                                      :is-sandboxed-user?    false
                                      :is-impersonated-user? false}
                                     (select-keys raw-ctx# [:current-user-perms
                                                            :is-superuser?
                                                            :is-sandboxed-user?
                                                            :is-impersonated-user?]))]
           ~@body))
       (mt/with-test-user :crowberto ~@body))))

(defn search-results
  "Perform search with the given search-string."
  ([search-string]
   (search-results search-string {}))
  ([search-string raw-ctx]
   (with-api-user raw-ctx
     (let [search-ctx (search.impl/search-context
                       (merge
                        (or *user-ctx*
                            {:current-user-id       api/*current-user-id*
                             :current-user-perms    @api/*current-user-permissions-set*
                             :is-superuser?         api/*is-superuser?*
                             :is-impersonated-user? (perms-util/impersonated-user?)
                             :is-sandboxed-user?    (perms-util/impersonated-user?)})
                        {:archived         false
                         :context          :default
                         :search-string    search-string
                         :models           search.config/all-models
                         :model-ancestors? false}
                        raw-ctx))]
       (search.engine/results search-ctx)))))
