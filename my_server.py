from http.server import HTTPServer, SimpleHTTPRequestHandler

import ssl
import os.path
import sys
import re

pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "([A-Z]+) (.*?) HTTP/[\d.]+" (\d{3})'


class MyStdout:
	def write(self, s):
		s = s.strip()
		if re.match(pattern, s):
			print(s)


sys.stderr = MyStdout()

cert_dir = "certificate"
html_dir = "html"


def get_ssl_context(certfile, keyfile):
	ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	ctx.load_cert_chain(certfile, keyfile)
	ctx.set_ciphers("@SECLEVEL=1:ALL")
	return ctx


class MyHandler(SimpleHTTPRequestHandler):
	def do_GET(self):
		page = open(os.path.join(html_dir, "index.html")).read()
		self.send_response(200)
		self.end_headers()
		self.wfile.write(bytes(page, "utf-8"))


def run_server():
	server = HTTPServer(("", 443), MyHandler)
	context = get_ssl_context(
		os.path.join(cert_dir, "cert.pem"),
		os.path.join(cert_dir, "key.pem")
	)
	server.socket = context.wrap_socket(server.socket, server_side=True)
	server.serve_forever()
