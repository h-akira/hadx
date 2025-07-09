import os

def login_required(func):
  def wrapper(master, **kwargs):
    if not master.request.auth:
      return {
        'statusCode': 302,
        'headers': {
          'Location': master.settings.AUTH_PAGE.get_login_url(master)
        }
      }
    return func(master, **kwargs)
  return wrapper

def get_login_url(master):
  return master.settings.AUTH_PAGE.get_login_url(master)

def get_signup_url(master):
  return master.settings.AUTH_PAGE.get_signup_url(master)

def reverse(master, app_name, **kwargs):
  path = master.router.name2path(app_name, kwargs)
  if master.local:
    MAPPING_PATH = master.settings.MAPPING_PATH_LOCAL
  else:
    MAPPING_PATH = master.settings.MAPPING_PATH
  if MAPPING_PATH.startswith("/"):
    MAPPING_PATH = MAPPING_PATH[1:]
  return os.path.join("/", MAPPING_PATH, path)

def static(master, file_path):
  if master.settings.STATIC_URL.startswith("/"):
    STATIC_URL = master.settings.STATIC_URL[1:]
  else:
    STATIC_URL = master.settings.STATIC_URL
  if master.local:
    MAPPING_PATH = master.settings.MAPPING_PATH_LOCAL
  else:
    MAPPING_PATH = master.settings.MAPPING_PATH
  if MAPPING_PATH.startswith("/"):
    MAPPING_PATH = MAPPING_PATH[1:]
  return os.path.join("/", MAPPING_PATH, STATIC_URL, file_path)

def redirect(master, app_name, **kwargs):
  return {
    "statusCode": 302,
    "headers": {
      "Location": reverse(master, app_name, **kwargs)
    }
  }

def gen_response(master, body, content_type="text/html; charset=UTF-8", code=200, isBase64Encoded: bool=None):
  response = {
    "statusCode": code,
    "headers": {
      "Content-Type": content_type
    },
    "body": body
  }
  if isBase64Encoded is not None:
    response["isBase64Encoded"] = isBase64Encoded
  # if master.request.auth and master.request.referrer:
  #   pass
  return response

def render(master, template_file, context={}, content_type="text/html; charset=UTF-8", code=200):
  import jinja2
  env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(master.settings.TEMPLATE_DIR),
  )
  env.globals['static'] = static
  env.globals['reverse'] = reverse
  env.globals['get_login_url'] = get_login_url
  env.globals['get_signup_url'] = get_signup_url
  template = env.get_template(template_file)
  if "master" not in context.keys():
    context["master"] = master
  return gen_response(master, template.render(**context), content_type, code)

def json_response(master, body, code=200):
  import json
  return gen_response(master, json.dumps(body), "application/json; charset=UTF-8", code)

def error_render(master, error_message=None):
  if master.settings.DEBUG:
    error_html= """\
<h1>Error</h1>
<h3>Error Message</h3>
{error_message}
<h3>event</h3>
{event}
<h3>Context</h3>
{context}
"""
    return gen_response(
      master, 
      error_html.format(error_message=error_message, event=master.event, context=master.context), 
      "text/html; charset=UTF-8", 
      200
    )
  else:
    error_html= """\
<h1>Error</h1>
<p>Sorry, an error occurred.</p>
<p>Please try again later, or contact the administrator.</p>
"""
    return gen_response(master, error_html, "text/html; charset=UTF-8", 500)
