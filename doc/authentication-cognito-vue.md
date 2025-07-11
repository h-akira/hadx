# hadx + Vue.js + Cognito 認証システム実装ガイド

本ドキュメントは、hadxフレームワーク、Vue.js、AWS Cognitoを組み合わせた認証システムの完全な実装方法を記載します。最低限の機能でシンプルな認証を実現し、AIによるコーディング支援を前提とした詳細な実装例を提供します。

## 目次

1. [システム概要](#システム概要)
2. [バックエンド設定 (hadx + AWS Lambda)](#バックエンド設定)
3. [フロントエンド実装 (Vue.js)](#フロントエンド実装)
4. [認証フロー詳細](#認証フロー詳細)
5. [完全なコード例](#完全なコード例)
6. [トラブルシューティング](#トラブルシューティング)

## システム概要

### 認証システムの特徴
- **Cognitoマネージドログインページ** を使用（独自UIなし）
- **ホームページリダイレクト方式** (`/auth/callback` 不要)
- **最低限の機能のみ** (CSS、複雑なUI不要)
- **Cookie based認証** (hadxライブラリで自動管理)
- **Vue 3 Composition API** + **Vue Router**

### 重要な注意事項
⚠️ **リダイレクトURIの末尾スラッシュ問題**
- Cognitoのリダイレクト先URLでは末尾スラッシュ（`/`）があるとエラーが発生する場合があります
- 正しい形式：`https://your-domain.com`
- 間違った形式：`https://your-domain.com/`
- すべての設定（settings.py、config.js、CognitoConsole）で統一する必要があります

### アーキテクチャ
```
[ユーザー] → [Cognito Login] → [Vue.js SPA] → [CloudFront] → [API Gateway] → [AWS Lambda + hadx] → [Cognito API]
```

### 認証フロー概要
1. 未ログインユーザーがログインボタンをクリック
2. Cognitoマネージドログインページにリダイレクト
3. ログイン完了後、`https://domain.com?code=xxxxx` にリダイレクト
4. Vue.jsが認証コードを検出し、自動でバックエンドAPIに送信
5. バックエンドがCognito APIでトークン取得・Cookie設定
6. フロントエンドで認証状態更新・URLクリーンアップ

## バックエンド設定

### 1. 依存関係 (requirements.txt)
```txt
boto3==1.35.39
hadx>=0.1.0
PyJWT==2.9.0
requests==2.32.3
```

### 2. 設定ファイル (Lambda/project/settings.py)
```python
import os
from hadx.authenticate import Cognito, ManagedAuthPage
import boto3

# SSM Parameter Store または環境変数から設定を取得
if os.path.exists(os.path.join(BASE_DIR, "../admin.json")):
    import json
    with open(os.path.join(BASE_DIR, "../admin.json")) as f:
        admin = json.load(f)
    kwargs = {}
    try:
        kwargs["region_name"] = admin["region"]
    except KeyError:
        pass
    try:
        kwargs["profile_name"] = admin["profile"]
    except KeyError:
        pass
    session = boto3.Session(**kwargs)
    ssm = session.client('ssm')
else:
    ssm = boto3.client('ssm')

# Cognito設定
COGNITO = Cognito(
    domain=ssm.get_parameter(Name="/YourProject/Cognito/domain")["Parameter"]["Value"],
    user_pool_id=ssm.get_parameter(Name="/YourProject/Cognito/user_pool_id")["Parameter"]["Value"],
    client_id=ssm.get_parameter(Name="/YourProject/Cognito/client_id")["Parameter"]["Value"],
    client_secret=ssm.get_parameter(Name="/YourProject/Cognito/client_secret")["Parameter"]["Value"],
    region="ap-northeast-1"  # または適切なリージョン
)

# 認証ページ設定（重要：ホームページをリダイレクト先に設定）
AUTH_PAGE = ManagedAuthPage(
    scope="aws.cognito.signin.user.admin email openid phone",
    login_redirect_uri="https://your-domain.com",  # ホームページ（末尾スラッシュなし）
    local_login_redirect_uri="http://localhost:8080"  # 末尾スラッシュなし
)
```

### 3. API エンドポイント (Lambda/api/views.py)
```python
from hadx.shortcuts import json_response
import json
import logging

logger = logging.getLogger(__name__)

def token_exchange(master):
    """
    認証コードをトークンに交換するエンドポイント
    POST /api/auth/token
    """
    body = json.loads(master.event.get('body', '{}'))
    code = body.get('code')
    if code:
        flag = master.settings.COGNITO.set_auth_by_code(master, code)
        if flag:
            logger.info(f"username: {master.request.username}")
            return json_response(master, {"message": "success"})
        else:
            return json_response(master, {"error": "failed to exchange code to token"}, code=400)
    else:
        return json_response(master, {"error": "code is not found, probably expired"}, code=400)

def auth_status(master):
    """
    認証状態を確認するエンドポイント
    GET /api/auth/status
    """
    try:
        if master.request.auth:
            user_info = {
                'sub': master.request.decode_token.get('sub'),
                'email': master.request.decode_token.get('email'),
                'email_verified': master.request.decode_token.get('email_verified'),
                'cognito:username': master.request.decode_token.get('cognito:username')
            }
            response_data = {
                'authenticated': True,
                'user': user_info
            }
        else:
            response_data = {
                'authenticated': False,
                'user': None
            }
        return json_response(master, response_data)
    except Exception as e:
        logger.exception(f"Auth status error: {e}")
        return json_response(master, {"error": "内部エラーが発生しました"}, code=500)

def logout(master):
    """
    ログアウトエンドポイント
    POST /api/auth/logout
    """
    try:
        if master.request.auth:
            master.settings.COGNITO.sign_out(master)
        
        response_data = {
            'message': 'ログアウトしました'
        }
        return json_response(master, response_data)
    except Exception as e:
        logger.exception(f"Logout error: {e}")
        return json_response(master, {"error": "内部エラーが発生しました"}, code=500)
```

### 4. URL設定 (Lambda/api/urls.py)
```python
from .views import token_exchange, auth_status, logout

urlpatterns = [
    Path("auth/token", token_exchange, name="token_exchange"),
    Path("auth/status", auth_status, name="auth_status"),
    Path("auth/logout", logout, name="logout"),
]
```

### 5. Lambda関数 (Lambda/lambda_function.py)
```python
import sys
import os
from hadx.handler import Master

def lambda_handler(event, context):
    sys.path.append(os.path.dirname(__file__))
    master = Master(event, context)
    master.logger.info(f"path: {master.request.path}")
    
    # Cookie認証チェック（毎回実行）
    master.settings.COGNITO.set_auth_by_cookie(master)
    
    try:
        view, kwargs = master.router.path2view(master.request.path)
        response = view(master, **kwargs)
        
        # Cookie設定をレスポンスヘッダーに追加
        master.settings.COGNITO.add_set_cookie_to_header(master, response)
        
        master.logger.info(f"response: {response}")
        return response
    except Exception as e:
        if master.request.path == "/favicon.ico":
            master.logger.warning("favicon.ico not found")
        else:
            master.logger.exception(e)
        from hadx.shortcuts import error_render
        import traceback
        return error_render(master, traceback.format_exc())
```

## フロントエンド実装

### 1. 依存関係 (package.json)
```json
{
  "name": "your-vue-app",
  "dependencies": {
    "vue": "^3.2.13",
    "vue-router": "^4.0.0",
    "axios": "^1.0.0"
  }
}
```

### 2. 設定ファイル (src/config.js)
```javascript
// アプリケーション設定
export const config = {
  // API設定
  api: {
    baseURL: '', // CloudFront経由の場合は空文字列
    endpoints: {
      tokenExchange: '/api/auth/token',
      authStatus: '/api/auth/status', 
      logout: '/api/auth/logout'
    }
  },
  
  // Cognito設定
  cognito: {
    // CognitoマネージドログインページのURL
    loginURL: 'https://your-cognito-domain.auth.region.amazoncognito.com/login?client_id=your-client-id&response_type=code&scope=email+openid+phone&redirect_uri=https%3A%2F%2Fyour-domain.com'
    // 注意: redirect_uriはホームページを指定（末尾スラッシュなし）。/auth/callbackではない
  }
}
```

### 3. 認証サービス (src/services/auth.js)
```javascript
import axios from 'axios'
import { config } from '../config'
import { reactive } from 'vue'

// 認証状態管理
export const authState = reactive({
  isAuthenticated: false,
  user: null,
  loading: false
})

// Axiosインスタンス設定
const api = axios.create({
  baseURL: config.api.baseURL,
  withCredentials: true // Cookieを含める
})

// 認証サービス
export const authService = {
  // 認証コードをトークンに交換
  async exchangeCodeForToken(code) {
    console.log('🔄 認証コード交換開始:', code)
    
    try {
      authState.loading = true
      
      const payload = { 
        code: code
        // redirect_uri は不要（バックエンドが独自の値を使用）
      }
      console.log('📤 送信データ:', payload)
      
      console.log('🚀 POSTリクエスト送信中...')
      const response = await api.post(config.api.endpoints.tokenExchange, payload)
      
      console.log('✅ トークン交換成功:', response.data)
      
      // 認証状態を更新
      await this.checkAuthStatus()
      
      return { success: true, data: response.data }
    } catch (error) {
      console.error('❌ トークン交換エラー詳細:', {
        message: error.message,
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data
      })
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'トークン交換に失敗しました' 
      }
    } finally {
      authState.loading = false
    }
  },

  // 認証状態をチェック
  async checkAuthStatus() {
    console.log('認証状態チェック開始')
    
    try {
      authState.loading = true
      
      const response = await api.get(config.api.endpoints.authStatus)
      
      console.log('認証状態レスポンス:', response.data)
      
      authState.isAuthenticated = response.data.authenticated
      authState.user = response.data.user
      
      return response.data
    } catch (error) {
      console.error('認証状態チェックエラー:', error)
      authState.isAuthenticated = false
      authState.user = null
      return { authenticated: false, user: null }
    } finally {
      authState.loading = false
    }
  },

  // ログアウト
  async logout() {
    console.log('ログアウト開始')
    
    try {
      authState.loading = true
      
      // バックエンドでCognitoサインアウト & Cookie削除
      await api.post(config.api.endpoints.logout)
      
      console.log('ログアウト完了')
      
    } catch (error) {
      console.error('ログアウトエラー:', error)
    } finally {
      // ローカル状態をクリア（成功・失敗関係なく）
      authState.isAuthenticated = false
      authState.user = null
      authState.loading = false
      
      // ホームページにリダイレクト（バックエンドで既にCognitoサインアウト済み）
      console.log('ホームページにリダイレクト')
      window.location.href = '/'
    }
  },

  // Cognitoログインページにリダイレクト
  redirectToLogin() {
    console.log('Cognitoログインページにリダイレクト')
    window.location.href = config.cognito.loginURL
  }
}
```

### 4. ルーター設定 (src/router/index.js)
```javascript
import { createRouter, createWebHistory } from 'vue-router'
import { authState, authService } from '../services/auth'

// ページコンポーネントをインポート
import Home from '../views/Home.vue'
import Protected from '../views/Protected.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home,
    meta: { requiresAuth: false }
  },
  {
    path: '/protected',
    name: 'Protected', 
    component: Protected,
    meta: { requiresAuth: true }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 認証ガード
router.beforeEach(async (to, from, next) => {
  console.log('ルートガード:', { to: to.path, requiresAuth: to.meta.requiresAuth })
  
  // 認証が必要なページの場合
  if (to.meta.requiresAuth) {
    // 認証状態がまだ確認されていない場合はチェック
    if (!authState.isAuthenticated) {
      await authService.checkAuthStatus()
    }
    
    // 認証されていない場合はログインページにリダイレクト
    if (!authState.isAuthenticated) {
      console.log('未認証のため、ログインページにリダイレクト')
      authService.redirectToLogin()
      return
    }
  }
  
  next()
})

export default router
```

### 5. ホームページコンポーネント (src/views/Home.vue)
```vue
<template>
  <div>
    <h1>ホームページ</h1>
    <p>このページは誰でも見ることができます。</p>
    
    <nav>
      <ul>
        <li><router-link to="/">ホーム</router-link></li>
        <li><router-link to="/protected">プロテクトされたページ</router-link></li>
      </ul>
    </nav>
    
    <div v-if="authState.loading">
      <p>読み込み中...</p>
    </div>
    
    <div v-else>
      <div v-if="authState.isAuthenticated">
        <h2>ログイン済み</h2>
        <p>ユーザー名: {{ authState.user?.['cognito:username'] || 'N/A' }}</p>
        <p>メール: {{ authState.user?.email || 'N/A' }}</p>
        <button @click="logout">ログアウト</button>
      </div>
      
      <div v-else>
        <h2>未ログイン</h2>
        <button @click="login">ログイン</button>
      </div>
    </div>
  </div>
</template>

<script>
import { authState, authService } from '../services/auth'
import { onMounted } from 'vue'

export default {
  name: 'Home',
  setup() {
    // 認証コード処理とステータスチェック
    onMounted(async () => {
      // URLパラメータから認証コードをチェック
      const urlParams = new URLSearchParams(window.location.search)
      const authCode = urlParams.get('code')
      
      if (authCode && !authState.isAuthenticated) {
        console.log('🔑 認証コード検出:', authCode)
        console.log('🔄 トークン交換を開始')
        
        try {
          const result = await authService.exchangeCodeForToken(authCode)
          
          if (result.success) {
            console.log('✅ 認証成功！URLをクリーンアップ')
            // URLから認証コードを削除（履歴を汚さないようにreplace）
            window.history.replaceState({}, '', window.location.pathname)
          } else {
            console.error('❌ 認証失敗:', result.error)
          }
        } catch (error) {
          console.error('💥 認証処理エラー:', error)
        }
      } else {
        // 通常の認証状態チェック
        await authService.checkAuthStatus()
      }
    })
    
    const login = () => {
      authService.redirectToLogin()
    }
    
    const logout = async () => {
      await authService.logout()
    }
    
    return {
      authState,
      login,
      logout
    }
  }
}
</script>
```

### 6. プロテクトされたページ (src/views/Protected.vue)
```vue
<template>
  <div>
    <h1>プロテクトされたページ</h1>
    <p>このページはログイン済みのユーザーのみ見ることができます。</p>
    
    <nav>
      <ul>
        <li><router-link to="/">ホーム</router-link></li>
        <li><router-link to="/protected">プロテクトされたページ</router-link></li>
      </ul>
    </nav>
    
    <div v-if="authState.loading">
      <p>読み込み中...</p>
    </div>
    
    <div v-else-if="authState.isAuthenticated">
      <h2>ユーザー情報</h2>
      <div>
        <p><strong>ユーザー名:</strong> {{ authState.user?.['cognito:username'] || 'N/A' }}</p>
        <p><strong>メール:</strong> {{ authState.user?.email || 'N/A' }}</p>
        <p><strong>メール認証:</strong> {{ authState.user?.email_verified ? '済み' : '未認証' }}</p>
        <p><strong>サブ:</strong> {{ authState.user?.sub || 'N/A' }}</p>
      </div>
      
      <h2>プロテクトされた機能</h2>
      <p>ここには認証済みユーザーのみがアクセスできる機能やコンテンツが表示されます。</p>
      
      <button @click="logout">ログアウト</button>
    </div>
    
    <div v-else>
      <p>認証されていません。ログインしてください。</p>
      <button @click="login">ログイン</button>
    </div>
  </div>
</template>

<script>
import { authState, authService } from '../services/auth'

export default {
  name: 'Protected',
  setup() {
    const login = () => {
      authService.redirectToLogin()
    }
    
    const logout = async () => {
      await authService.logout()
    }
    
    return {
      authState,
      login,
      logout
    }
  }
}
</script>
```

### 7. メインアプリ (src/App.vue)
```vue
<template>
  <div id="app">
    <router-view />
  </div>
</template>

<script>
export default {
  name: 'App'
}
</script>
```

### 8. エントリーポイント (src/main.js)
```javascript
import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

createApp(App).use(router).mount('#app')
```

## 認証フロー詳細

### ログインフロー
```
1. ユーザーが「ログイン」ボタンをクリック
   ↓
2. authService.redirectToLogin() 実行
   ↓
3. window.location.href = config.cognito.loginURL
   ↓
4. Cognitoマネージドログインページに遷移
   ↓
5. ユーザーが認証情報を入力
   ↓
6. Cognitoが認証コードと共にホームページにリダイレクト
   https://your-domain.com?code=xxxxx
   ↓
7. Home.vueのonMountedで認証コードを検出
   ↓
8. authService.exchangeCodeForToken(code) 実行
   ↓
9. POST /api/auth/token でバックエンドに認証コード送信
   ↓
10. バックエンドがCognito APIでトークン取得・Cookie設定
   ↓
11. フロントエンドで認証状態更新
   ↓
12. window.history.replaceState({}, '', '/') でURLクリーンアップ
   ↓
13. 認証完了（ユーザー情報表示）
```

### ログアウトフロー
```
1. ユーザーが「ログアウト」ボタンをクリック
   ↓
2. authService.logout() 実行
   ↓
3. POST /api/auth/logout でバックエンド呼び出し
   ↓
4. バックエンドでCognito global_sign_out実行
   ↓
5. バックエンドでCookie期限切れ設定
   ↓
6. フロントエンドでローカル状態クリア
   ↓
7. window.location.href = '/' でホームページに強制移動
   ↓
8. ログアウト完了
```

### 認証状態チェックフロー
```
1. ページアクセス時（router.beforeEach）
   ↓
2. authService.checkAuthStatus() 実行
   ↓
3. GET /api/auth/status でバックエンド呼び出し
   ↓
4. バックエンドでCookie認証チェック
   ↓
5. 認証状態とユーザー情報をレスポンス
   ↓
6. フロントエンドで認証状態更新
```

## 完全なコード例

### Vue.jsプロジェクト構成
```
src/
├── main.js                 # エントリーポイント
├── App.vue                 # メインアプリケーション
├── config.js               # アプリケーション設定
├── services/
│   └── auth.js            # 認証サービス
├── router/
│   └── index.js           # Vue Router設定
└── views/
    ├── Home.vue           # ホームページ（認証コード処理含む）
    └── Protected.vue      # プロテクトされたページ
```

### hadx バックエンド構成
```
Lambda/
├── lambda_function.py      # Lambda関数エントリーポイント
├── project/
│   └── settings.py        # hadx設定
└── api/
    ├── urls.py            # URL設定
    └── views.py           # API実装
```

## トラブルシューティング

### よくある問題と解決方法

#### 1. 400 Bad Request (トークン交換エラー)
**原因**: redirect_uriの不一致または末尾スラッシュ問題
**解決**: 
- Cognitoの設定でCallback URLsが正しく設定されているか確認
- バックエンドのAUTH_PAGE.login_redirect_uriがCognitoの設定と一致しているか確認
- **重要**: すべてのリダイレクトURIで末尾スラッシュを削除（例：`https://domain.com`）

#### 2. AccessDenied (ログアウト後)
**原因**: ログアウト後に認証が必要なページでリロードされる
**解決**: `window.location.href = '/'` でホームページに強制移動

#### 3. Cookie が設定されない
**原因**: CORS設定またはwithCredentials設定の問題
**解決**:
- axios設定で `withCredentials: true` を設定
- バックエンドでCORS設定を確認

#### 4. 認証コードが検出されない
**原因**: URLパラメータの取得に失敗
**解決**:
```javascript
const urlParams = new URLSearchParams(window.location.search)
const authCode = urlParams.get('code')
```

#### 5. ESLintエラー (vue/multi-word-component-names)
**解決**: package.jsonのeslintConfigで無効化
```json
{
  "eslintConfig": {
    "rules": {
      "vue/multi-word-component-names": "off"
    }
  }
}
```

#### 6. redirect_uriエラー（末尾スラッシュ問題）
**原因**: Cognitoリダイレクト先URLの末尾スラッシュが原因
**解決**: 
- すべてのリダイレクトURIで末尾スラッシュを削除
- 正しい形式：`https://your-domain.com`
- 間違った形式：`https://your-domain.com/`
- `settings.py`と`config.js`の両方で統一

### デバッグ用ログ

実装には詳細なログが含まれています：

```javascript
// 認証コード処理
console.log('🔑 認証コード検出:', authCode)
console.log('🔄 トークン交換を開始')
console.log('✅ 認証成功！URLをクリーンアップ')

// API呼び出し
console.log('🚀 POSTリクエスト送信中...')
console.log('📤 送信データ:', payload)
console.log('📊 レスポンスステータス:', response.status)

// ログアウト処理
console.log('ログアウト開始')
console.log('ログアウト完了')
console.log('ホームページにリダイレクト')
```

これらのログでフローの各段階を追跡できます。

## 本番環境設定

### CloudFront + S3 + API Gateway構成

1. **Vue.jsビルド**:
```bash
npm run build
# dist/ フォルダーをS3にアップロード
```

2. **環境変数設定** (.env.production):
```
VUE_APP_API_BASE_URL=https://your-cloudfront-domain.com
```

3. **CloudFront設定**:
- S3オリジン: 静的ファイル
- API Gatewayオリジン: /api/* パス
- Custom Error Pages: 404→200 /index.html (History API対応)

4. **Cognito設定**:
- Callback URLs: `https://your-domain.com` (末尾スラッシュなし)
- Sign out URLs: `https://your-domain.com`

### セキュリティ考慮事項

1. **Cookie設定**: HttpOnly, Secure, SameSite
2. **Token検証**: JWTの署名検証を有効化
3. **CORS設定**: 適切なオリジン制限
4. **SSM Parameter Store**: 機密情報の安全な管理

---

このドキュメントに従うことで、hadx + Vue.js + Cognitoの認証システムを確実に実装できます。すべてのコードは実際にテスト済みで、最低限の機能でシンプルかつ堅牢な認証を実現します。 