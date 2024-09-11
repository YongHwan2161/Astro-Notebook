#pragma once

#include <functional>
#include <unordered_map>
#include <string>
#include <event2/http.h>
#include <openssl/ssl.h>

struct SSLInfo {
    SSL_CTX *ctx;
    SSL *ssl;
};

class Router {
public:
    using HandlerFunction = std::function<void(struct evhttp_request*, SSLInfo*)>;
    using QueryHandlerFunction = std::function<void(struct evhttp_request*, SSLInfo*, const std::string&)>;
    using StaticRouteHandlerFunction = std::function<void(SSLInfo*, struct evhttp_request*, const std::string&)>;

    void addRoute(const std::string& path, HandlerFunction handler, evhttp_cmd_type method);
    void addQueryRoute(const std::string& path, QueryHandlerFunction handler);
    void addStaticRoute(const std::string& prefix, StaticRouteHandlerFunction handler);
    void handleRequest(struct evhttp_request* req, SSLInfo* ssl_info);

private:
    std::unordered_map<evhttp_cmd_type, std::unordered_map<std::string, HandlerFunction>> routes;
    std::unordered_map<std::string, QueryHandlerFunction> queryRoutes;
    std::unordered_map<std::string, StaticRouteHandlerFunction> staticRoutes;
};