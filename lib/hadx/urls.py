import importlib
import os
from hads.handler import Master

class NotMatched(Exception):
  """URLパターンが一致しなかった場合に発生する例外"""
  pass

class KwargsRemain(Exception):
  """URL生成時に使用されなかったキーワード引数がある場合に発生する例外"""
  pass

class Path:
  """URLパスパターンを表すクラス"""
  def __init__(self, path_pattern: str, view, name=None):
    """
    Args:
        path_pattern: URLパスパターン（例: 'users/{user_id}'）
        view: パスに対応するビュー関数
        name: パスの名前（リバースルックアップに使用）
    """
    if path_pattern == "":
      self.segments = []
    elif path_pattern[0] == "/":
      raise ValueError("パスパターンは / で始まってはいけません")
    else:
      self.segments = path_pattern.split('/')
    self.path_pattern = path_pattern
    self.view = view
    self.name = name

class Router:
  """URLルーティングを処理するクラス"""
  def __init__(self, root="", urls_str="project.urls", name=None):
    """
    Args:
        root: ルートパス
        urls_str: URLパターンを含むモジュールのインポートパス
        name: ルーターの名前
    """
    urls = importlib.import_module(urls_str)
    self.urlpatterns = urls.urlpatterns
    self.root = root
    self.name = name
    if self.root == "":
      self.segments = []
    elif self.root[0] == "/":
      raise ValueError("ルートパスは / で始まってはいけません")
    else:
      self.segments = self.root.split('/')
    try:
      self.app_name = urls.app_name
    except AttributeError:
      self.app_name = None
  def name2path(self, name: str, kwargs={}, root=""):
    """
    名前からURLパスを生成します。
    
    Args:
        name: 名前（例: 'app:user_detail'）
        kwargs: パスパラメータの値
        root: ルートパス
        
    Returns:
        生成されたURLパス
        
    Raises:
        NotMatched: 名前に一致するパスが見つからない場合
        KwargsRemain: 使用されなかったキーワード引数がある場合
    """
    name_list = name.split(":")
    for urlpattern in self.urlpatterns:
      if urlpattern.__class__ is Path:
        if len(name_list) != 1:
          continue
        if urlpattern.name == name_list[0]:
          formatted, kwargs = _step_format(urlpattern.path_pattern, kwargs)
          if kwargs:
            raise KwargsRemain("未使用のキーワード引数があります: " + ", ".join(kwargs.keys()))
          else:
            return os.path.join(root, formatted)
      elif urlpattern.__class__ is self.__class__:
        if len(name_list) == 1:
          raise ValueError("ネストされたルーターには複数の名前要素が必要です")
        if urlpattern.name == name_list[0]:
          new_root, kwargs = _step_format(urlpattern.root, kwargs)
          return urlpattern.name2path(":".join(name_list[1:]), kwargs, root=os.path.join(root, new_root))
    raise NotMatched(f"名前 '{name}' に一致するパスが見つかりません")
  def path2view(self, abs_path=None, segments=None, kwargs={}):
    """
    パスからビュー関数を取得します。
    
    Args:
        abs_path: 絶対パス（例: '/users/123'）
        segments: パスセグメントのリスト
        kwargs: パスパラメータの値
        
    Returns:
        (view, kwargs)のタプル
        
    Raises:
        NotMatched: パスに一致するビューが見つからない場合
    """
    if abs_path is not None and segments is not None:
      raise ValueError("abs_pathとsegmentsは同時に指定できません")
    if abs_path is None and segments is None:
      raise ValueError("abs_pathまたはsegmentsを指定する必要があります")
    if abs_path is not None:
      if len(abs_path) > 1 and abs_path[-1] == "/":
        abs_path = abs_path[:-1]
      segments = self._abs_path2segments(abs_path)
    
    routers = []
    for urlpattern in self.urlpatterns:
      if urlpattern.__class__ is Path:
        flag, kwargs = self._matching_chercker(segments, urlpattern.segments, mode="path")
        if flag:
          return urlpattern.view, kwargs
      elif urlpattern.__class__ is self.__class__:
        routers.append(urlpattern)
      else:
        raise TypeError("urlpatternはPathまたはRouterである必要があります")
    
    for router in routers:
      remaining_segments, kwargs = self._matching_chercker(segments, router.segments, mode="router", kwargs=kwargs)
      if remaining_segments != False:
        return router.path2view(segments=remaining_segments, kwargs=kwargs)
    
    raise NotMatched(f"パス '{'/'.join(segments) if segments else '/'}' に一致するビューが見つかりません")
  def _abs_path2segments(self, abs_path):
    """
    絶対パスをセグメントのリストに変換します。
    
    Args:
        abs_path: 絶対パス（例: '/users/123'）
        
    Returns:
        セグメントのリスト（例: ['users', '123']）
    """
    if not abs_path:
      raise ValueError("abs_pathは空であってはいけません")
      
    if abs_path == "/":
      return []
    elif abs_path[0] == "/":
      return abs_path[1:].split('/')
    else:
      raise ValueError("abs_pathは / で始まる必要があります")
      
  def _matching_chercker(self, segments, pattern_segments, mode, kwargs={}):
    """
    パスセグメントがパターンに一致するかチェックします。
    
    Args:
        segments: パスセグメントのリスト
        pattern_segments: パターンセグメントのリスト
        mode: 'path'または'router'
        kwargs: パスパラメータの値
        
    Returns:
        modeが'path'の場合: (一致したかどうか, 更新されたkwargs)
        modeが'router'の場合: (残りのセグメント, 更新されたkwargs)または(False, kwargs)
    """
    _kwargs = kwargs.copy()
    if mode not in ["path", "router"]:
      raise ValueError("modeは'path'または'router'である必要があります")
      
    if len(segments) < len(pattern_segments):
      return False, kwargs
      
    for i, p in enumerate(pattern_segments):
      if p[0] == "{" and p[-1] == "}":
        _kwargs[p[1:-1]] = segments[i]
        continue
      else:
        if segments[i] != p:
          return False, kwargs
          
    # パターンの全セグメントをチェックした後
    if mode == "path":
      if len(segments) == len(pattern_segments):
        return True, _kwargs
      else:
        return False, kwargs
    else:  # mode == "router"
      if segments == []:
        return segments, _kwargs
      elif len(segments) == len(pattern_segments):
        return False, kwargs
      else:
        if len(pattern_segments) == 0:
          return segments, _kwargs
        else:
          return segments[i+1:], _kwargs

def _step_format(text: str, kwargs: dict):
  """
  テキスト内のプレースホルダーを値で置き換えます。
  
  Args:
      text: フォーマット文字列（例: 'users/{user_id}'）
      kwargs: 置換する値の辞書
      
  Returns:
      (フォーマット済みテキスト, 未使用のkwargs)のタプル
  """
  exec_kwargs = {}  # 使用するキーワード引数
  return_kwargs = {}  # 未使用のキーワード引数
  
  for k, v in kwargs.items():
    if "{"+k+"}" in text:
      exec_kwargs[k] = v
    else:
      return_kwargs[k] = v
      
  return text.format(**exec_kwargs), return_kwargs

