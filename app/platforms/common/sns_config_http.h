#pragma once
#include <curl/curl.h>
/* Retail Shell CWebRequest::BStart 0xcc2198-0xcc21b4. Completion maps
 * CURLE_OK to IWebRequest=4; HTTP >=400 reaches the error path via curl.
 * Keep port-local TLS verification and bounded deadlines explicit. */
static inline void sl_sns_config_http_options(CURL *request) {
    curl_easy_setopt(request, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(request, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(request, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(request, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(request, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(request, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    curl_easy_setopt(request, CURLOPT_TIMEOUT_MS, 25000L);
}
