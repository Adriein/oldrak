from mitmproxy import http, tcp


class Network:
    def __init__(self):
        print("constructed network")
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

    def tcp_message(self, tcp_flow: tcp.TCPFlow):
        print("tcp")
        if tcp_flow.messages:
            last_message = tcp_flow.messages[-1]
            direction = "→ server" if last_message.from_client else "← client"
            data = last_message.content
            print(f"{direction} {len(data)} bytes: {data[:50]!r}")