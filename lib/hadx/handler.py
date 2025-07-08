import urllib.parse
import importlib
import os
import json
import logging

class Master:
  """
  リクエスト処理の中心となるクラス。
  
  AWS Lambda関数のハンドラーから呼び出され、リクエストの処理を行います。
  """
  def __init__(self, event, context):
    """
    Args:
        event: AWS Lambdaイベントオブジェクト
        context: AWS Lambdaコンテキストオブジェクト
    """
    from hads.urls import Router
    self.event = event
    self.context = context
    self.settings = importlib.import_module('project.settings') 
    self.router = Router()
    self.request = Request(event, context)
    self._set_logger()
    self._set_local()
    
  def _set_local(self):
    """ローカル開発環境かどうかを判定します。"""
    AWS_SAM_LOCAL = os.getenv("AWS_SAM_LOCAL")
    if AWS_SAM_LOCAL is None:
      # 環境変数がない場合はadmin.jsonの存在で判断
      if os.path.isfile(os.path.join(self.settings.BASE_DIR, '../admin.json')):
        self.local = True
      else:
        self.local = False
    else:
      if AWS_SAM_LOCAL == "true":
        self.local = True
      elif AWS_SAM_LOCAL == "false":
        self.local = False
      else:
        raise ValueError("AWS_SAM_LOCALは'true'または'false'である必要があります")
        
  def _set_logger(self):
    """ロガーを設定します。"""
    self.logger = logging.getLogger()
    self.logger.setLevel(logging.INFO)

class Request:
  """
  HTTPリクエストを表すクラス。
  
  リクエストメソッド、パス、ボディ、認証情報などを保持します。
  """
  def __init__(self, event, context):
    """
    Args:
        event: AWS Lambdaイベントオブジェクト
        context: AWS Lambdaコンテキストオブジェクト
    """
    self.method = event['requestContext']["httpMethod"]
    self.path = event['path']
    self._set_parsed_body(event)
    
    # 認証関連の属性
    self.auth = False
    self.username = None
    self.set_cookie = False
    self.clean_cookie = False
    self.access_token = None
    self.id_token = None
    self.refresh_token = None
    self.decode_token = None
    
  def set_token(self, access_token, id_token, refresh_token):
    """認証トークンを設定します。"""
    self.access_token = access_token
    self.id_token = id_token
    self.refresh_token = refresh_token
    
  def _set_parsed_body(self, event):
    """リクエストボディを解析します。"""
    if event["requestContext"]["httpMethod"] == "POST" and 'body' in event:
      self.body = urllib.parse.parse_qs(event['body'] or '')
      # 単一値のパラメータを簡略化
      for key, value in self.body.items():
        if len(value) == 1:
          self.body[key] = value[0]
    else:
      self.body = None

