# このファイルは非推奨です。代わりに shortcuts.py を使用してください。
import os
import warnings

warnings.warn(
    "shourtcuts モジュールは非推奨です。代わりに shortcuts モジュールを使用してください。",
    DeprecationWarning,
    stacklevel=2
)

# 互換性のために shortcuts.py からすべての関数をインポート
from hads.shortcuts import (
    login_required, get_login_url, get_signup_url, reverse, static,
    redirect, gen_response, render, json_response, error_render
)
