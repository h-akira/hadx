import os
import http.server
import socketserver
import urllib.request
from urllib.parse import urlparse

def run_static_server(static_url, static_dir, port=8080):
  """
  静的ファイルを提供するサーバーを実行します。
  
  Args:
      static_url: 静的ファイルのURLパス（例: '/static'）
      static_dir: 静的ファイルのディレクトリパス
      port: サーバーのポート番号（デフォルト: 8080）
  """
  class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
      if path.startswith(static_url):
        return os.path.join(os.getcwd(), path[1:])
      else:
        return None
        
    def do_GET(self):
      path = self.translate_path(self.path)
      if path:
        if os.path.exists(path) and os.path.isfile(path):
          super().do_GET()
        else:
          self.send_error(404, "File Not Found")
      else:
        self.send_error(403, "Forbidden")
        
  with socketserver.TCPServer(("localhost", port), MyHTTPRequestHandler) as httpd:
    print(f"静的ファイルサーバーを起動しました: http://localhost:{port}{static_url}")
    httpd.serve_forever()

def run_proxy_server(static_url, port=8000, sam_port=3000, static_port=8080):
  """
  リバースプロキシサーバーを実行します。
  
  静的ファイルリクエストは static_port に、その他のリクエストは sam_port に転送します。
  
  Args:
      static_url: 静的ファイルのURLパス（例: '/static'）
      port: プロキシサーバーのポート番号（デフォルト: 8000）
      sam_port: SAM Localサーバーのポート番号（デフォルト: 3000）
      static_port: 静的ファイルサーバーのポート番号（デフォルト: 8080）
  """
  class ReverseProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
      parsed_url = urlparse(self.path)
      if parsed_url.path.startswith(static_url):
        target_url = f'http://localhost:{static_port}{self.path}'
      else:
        target_url = f'http://localhost:{sam_port}{self.path}'
      try:
        with urllib.request.urlopen(target_url) as response:
          self.send_response(response.status)
          self.send_header('Content-type', response.headers.get('Content-type', 'text/html'))
          self.end_headers()
          self.wfile.write(response.read())
      except urllib.error.URLError as e:
        self.send_error(500, str(e.reason))
        
  httpd = http.server.HTTPServer(('localhost', port), ReverseProxyHandler)
  print(f"プロキシサーバーを起動しました: http://localhost:{port}")
  print(f"- 静的ファイル ({static_url}*) は port {static_port} に転送")
  print(f"- その他のリクエストは port {sam_port} に転送")
  httpd.serve_forever()
