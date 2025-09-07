from mitmproxy import http


class Network:
    def __init__(self):
        pass

    def request(self, http_flow: http.HTTPFlow):
        """Handles a request packet.

        Args:
            http_flow (http.HTTPFlow): The HTTP flow to handle.
        """
        # Ignore requests, we only care about TCP messages.
        print(f"\n -> {http_flow.request.pretty_url}: {http_flow.request.text[:1024]}")

    def response(self, http_flow: http.HTTPFlow):
        """Handles a response packet.

        Args:
            http_flow (http.HTTPFlow): The HTTP flow to handle.
        """
        # Ignore responses, we only care about TCP messages.
        print(f"\n <- {http_flow.request.pretty_url}: {http_flow.response.text[:1024]}")