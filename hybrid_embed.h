/*
 * Embedding API: link hybrid-provider into another provider (the "host") as a
 * static library instead of loading it as its own module. The host forwards its
 * own core handle and dispatch table, merges hybrid_embed_query() results into
 * its query_operation answer and hybrid_embed_get_capabilities() into its
 * get_capabilities answer, and calls hybrid_embed_teardown() from its teardown.
 *
 * The embedded algorithms are then registered under the HOST's provider name
 * (e.g. provider=oqsprovider). Components are still fetched via EVP from the
 * application's library context, so the host's own algorithms can serve as
 * components.
 *
 * Built only with -DHYBRID_EMBEDDED (CMake target `hybrid-embed`).
 */
#ifndef HYBRID_EMBED_H
#define HYBRID_EMBED_H

#include <openssl/core.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialise an embedded instance. Call from the host's OSSL_provider_init
 * with the handle and `in` dispatch the core gave the host. Config keys
 * (cede-to-default, alg<N>-propquery, ...) are read from the host's provider
 * config section. `allow` (may be NULL = everything) selects which hybrid /
 * composite algorithms are exposed; rejected ones are neither queryable nor
 * advertised as TLS groups / sigalgs, and their OIDs are not registered.
 *
 * `resolve` (required) maps the host's provctx back to *hctx: OpenSSL passes the
 * host's provctx to every algorithm function the host registered, including
 * the embedded ones, so they need a way back to their own context.
 * Returns 1 on success and sets *hctx.
 */
int hybrid_embed_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      int (*allow)(const char *alg_name),
                      void *(*resolve)(void *host_provctx), void **hctx);

/* The algorithm table for `operation_id` (OSSL_OP_*), or NULL. Immutable
 * after init; safe to cache. */
const OSSL_ALGORITHM *hybrid_embed_query(void *hctx, int operation_id);

/* Same contract as OSSL_FUNC_provider_get_capabilities. */
int hybrid_embed_get_capabilities(void *hctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg);

void hybrid_embed_teardown(void *hctx);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_EMBED_H */
