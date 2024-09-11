#include "router.h"
#include <iostream>

void Router::addRoute(const std::string &path, HandlerFunction handler, evhttp_cmd_type method)
{
    routes[method][path] = std::move(handler);
}

void Router::addQueryRoute(const std::string &path, QueryHandlerFunction handler)
{
    queryRoutes[path] = std::move(handler);
}

void Router::addStaticRoute(const std::string &prefix, StaticRouteHandlerFunction handler)
{
    staticRoutes[prefix] = std::move(handler);
}

void Router::handleRequest(struct evhttp_request *req, SSLInfo *ssl_info)
{
    const char *uri = evhttp_request_get_uri(req);
    evhttp_cmd_type method = evhttp_request_get_command(req);

    try
    {
        std::string path(uri);
        std::string query;
        size_t query_pos = path.find('?');
        if (query_pos != std::string::npos)
        {
            query = path.substr(query_pos + 1);
            path = path.substr(0, query_pos);
        }
        if (path == "/")
        {
            path = "/index.html";
        }
        // Check static routes
        for (const auto &[prefix, handler] : staticRoutes)
        {
            if (path.find(prefix) == 0)
            {
                handler(ssl_info, req, path.substr(1));
                return;
            }
        }

        // Check query routes
        auto queryIt = queryRoutes.find(path);
        if (queryIt != queryRoutes.end())
        {
            queryIt->second(req, ssl_info, query);
            return;
        }

        // Check regular routes
        auto methodIt = routes.find(method);
        if (methodIt != routes.end())
        {
            auto handlerIt = methodIt->second.find(path);
            if (handlerIt != methodIt->second.end())
            {
                handlerIt->second(req, ssl_info);
                return;
            }
        }

        // 404 Not Found
        evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error handling request: " << e.what() << std::endl;
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
    }
}