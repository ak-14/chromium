def main(request, response):

    headers = [("Content-type", request.headers.get("Content-Type", "text/plain"))]

    if "content" in request.GET:
        content = request.GET.first("content")
    else:
        content = request.body

    return headers, content
