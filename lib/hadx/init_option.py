import sys
import os
import json

SETTINGS_PY_TEMPLATE = """\
import os
MAPPING_PATH = "stage-01"  # API Gatewayをそのまま使う場合はステージ名、独自ドメインを使う場合は空文字列、Localでは空文字列に上書き
MAPPING_PATH_LOCAL = ""  # API Gatewayをそのまま使う場合はステージ名、独自ドメインを使う場合は空文字列、Localでは空文字列に上書き
DEBUG = True
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_URL = "/static"  # 先頭の/はあってもなくても同じ扱

# ログイン周りの設定
# from hads.authenticate import Cognito, ManagedAuthPage
# import boto3
# if os.path.exists(os.path.join(BASE_DIR, "../admin.json")):
#   import json
#   with open(os.path.join(BASE_DIR, "../admin.json")) as f:
#     admin = json.load(f)
#   kwargs = {{}}
#   try:
#     kwargs["region_name"] = admin["region"]
#   except KeyError:
#     pass
#   try:
#     kwargs["profile_name"] = admin["profile"]
#   except KeyError:
#     pass
#   session = boto3.Session(**kwargs)
#   ssm = session.client('ssm')
# else:
#   ssm = boto3.client('ssm')
# COGNITO= Cognito(
#   domain = ssm.get_parameter(Name="path to parameter")["Parameter"]["Value"],
#   user_pool_id = ssm.get_parameter(Name="path to parameter")["Parameter"]["Value"],
#   client_id = ssm.get_parameter(Name="path to parameter")["Parameter"]["Value"],
#   client_secret = ssm.get_parameter(Name="path to parameter")["Parameter"]["Value"],
#   region = "{REGION}",
# )
# AUTH_PAGE = ManagedAuthPage(
#   scope = "aws.cognito.signin.user.admin email openid phone",
#   login_redirect_uri = ssm.get_parameter(Name="path to parameter")["Parameter"]["Value"],
#   local_login_redirect_uri = "http://localhost:3000"
# )
"""

URLS_PY_TEMPLATE = """\
# from hads.urls import Path, Router
# from .views import ...

urlpatterns = [
  # Path("AAA/MMM/NNN", "AAAFunction", name="AAA"),
  # Router("BBB", "BBB.urls", name="BBB")
]
"""

LAMBDA_FUNCTION_PY_TEMPLATE = """\
import sys
import os
from hads.handler import Master

def lambda_handler(event, context):
  sys.path.append(os.path.dirname(__file__))
  master = Master(event, context)
  master.logger.info(f"path: {master.request.path}")
  # master.settings.COGNITO.set_auth_by_code(master)
  # master.settings.COGNITO.set_auth_by_cookie(master)
  try:
    view, kwargs = master.router.path2view(master.request.path)
    response = view(master, **kwargs)
    # master.settings.COGNITO.add_set_cookie_to_header(master, response)
    master.logger.info(f"response: {response}")
    return response
  except Exception as e:
    if master.request.path == "/favicon.ico":
      master.logger.warning("favicon.ico not found")
    else:
      master.logger.exception(e)
    from hads.shourtcuts import error_render
    import traceback
    return error_render(master, traceback.format_exc())
"""

TEMPLATE_YAML_TEMPLATE = """\
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  AWSGITEST

  Sample SAM Template for AWSGITEST

# More info about Globals: https://github.com/awslabs/serverless-application-model/blob/master/docs/globals.rst
Globals:
  Function:
    Timeout: 30
    Tracing: Active
    MemorySize: 256
    # You can add LoggingConfig parameters such as the Logformat, Log Group, and SystemLogLevel or ApplicationLogLevel. Learn more here https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-loggingconfig.
  Api:
    TracingEnabled: true
Resources:
  MainAPIGateway:
    Type: AWS::Serverless::Api
    Properties:
      Name: '{APIGW_NAME}'
      StageName: 'stage-01'
  MainFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: '{FUNCTION_NAME}'
      CodeUri: Lambda/
      Handler: lambda_function.lambda_handler
      Runtime: python{PYTHON_VERSION}
      # Layers:
      #   - !Ref MainLayer
      Role: !GetAtt LambdaExecutionRole.Arn
      LoggingConfig:
        LogFormat: JSON
      Events:
        ApiRoot:
          Type: Api
          Properties:
            Path: '/'
            Method: ANY
            RestApiId:
              Ref: MainAPIGateway
        ApiProxy:
          Type: Api
          Properties:
            Path: '/{{proxy+}}'
            Method: ANY
            RestApiId:
              Ref: MainAPIGateway
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: "Allow"
            Principal:
              Service: lambda.amazonaws.com
            Action: "sts:AssumeRole"
      ManagedPolicyArns:
        - "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        # - "arn:aws:iam::aws:policy/AmazonCognitoPowerUser"
  # MainLayer:
  #   Type: AWS::Serverless::LayerVersion
  #   Properties:
  #     LayerName: '{LAYER_NAME}'
  #     ContentUri: Layer/
  #     CompatibleRuntimes:
  #       - python{PYTHON_VERSION}
  ApplicationResourceGroup:
    Type: AWS::ResourceGroups::Group
    Properties:
      Name:
        Fn::Sub: ApplicationInsights-SAM-${{AWS::StackName}}
      ResourceQuery:
        Type: CLOUDFORMATION_STACK_1_0
  ApplicationInsightsMonitoring:
    Type: AWS::ApplicationInsights::Application
    Properties:
      ResourceGroupName:
        Ref: ApplicationResourceGroup
      AutoConfigurationEnabled: 'true'
Outputs:
  # ServerlessRestApi is an implicit API created out of Events key under Serverless::Function
  # Find out more about other implicit resources you can reference within SAM
  # https://github.com/awslabs/serverless-application-model/blob/master/docs/internals/generated_resources.rst#api
  HelloWorldApi:
    Description: API Gateway endpoint URL for Prod stage for Hello World function
    Value: !Sub "https://${{MainAPIGateway}}.execute-api.${{AWS::Region}}.amazonaws.com/stage-01/"
""" 

SAMCONFIG_TOML_TEMPLATE = """\
# More information about the configuration file can be found here:
# https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html
version = 0.1

[default.global.parameters]
stack_name = "{STACK_NAME}"

[default.build.parameters]
cached = true
parallel = true

[default.validate.parameters]
lint = true

[default.deploy.parameters]
capabilities = "CAPABILITY_NAMED_IAM"
confirm_changeset = true
resolve_s3 = true
region = "{REGION}"

[default.package.parameters]
resolve_s3 = true

[default.sync.parameters]
watch = true

[default.local_start_api.parameters]
warm_containers = "EAGER"

[default.local_start_lambda.parameters]
warm_containers = "EAGER"
"""

ADMIN_JSON = {
  "region": None,
  "profile": None,
  "static":{
    "local": "static",
    "s3": None
  },
  "local_server":{
    "port":{
      "static":8080,
      "proxy":8000,
      "sam":3000
    }
  }
}



def gen_templates():
  project_name = input("Enter project name (directory name): ")
  if not project_name:
    print("Project name is required")
    return False
  for w in [" ", "/", "\\", ":", "*", "?", "\"", "<", ">", "|", "!", "@", "#", "$", "%", "^", "&", "(", ")", "[", "]", "{", "}", "+", "=", ",", ";", "`", "~", "'"]:
    if w in project_name:
      print("Project name cannot contain '{w}'".format(w=w))
      return False
  if os.path.exists(project_name):
    print("Project already exists")
    return False
  suffix = input("Enter suffix (to make resources unique, default is same as project name): ")
  if not suffix:
    suffix = project_name
  python_version = input("Enter python version (default is 3.12): ")
  if not python_version:
    python_version = "3.12"
  region = input("Enter region (default is ap-northeast-1): ")
  if not region:
    region = "ap-northeast-1"
  # 作成開始
  os.makedirs(project_name)
  os.makedirs(os.path.join(project_name, "Lambda"))
  os.makedirs(os.path.join(project_name, "Lambda/project"))
  os.makedirs(os.path.join(project_name, "Lambda/templates"))
  kwargs = {
    "APIGW_NAME": f"api-{suffix}",
    "LAYER_NAME": f"layer-{suffix}",
    "PYTHON_VERSION": python_version,
    "FUNCTION_NAME": f"lambda-{suffix}"
  }
  with open(os.path.join(project_name, "template.yaml"), "w") as f:
    f.write(TEMPLATE_YAML_TEMPLATE.format(**kwargs))
  kwargs = {
    "REGION": region,
    "STACK_NAME": f"stack-{suffix}"
  }
  with open(os.path.join(project_name, "samconfig.toml"), "w") as f:
    f.write(SAMCONFIG_TOML_TEMPLATE.format(**kwargs))
  with open(os.path.join(project_name, "Lambda/lambda_function.py"), "w") as f:
    f.write(LAMBDA_FUNCTION_PY_TEMPLATE)
  kwargs = {
    "REGION": region
  }
  with open(os.path.join(project_name, "Lambda/project/settings.py"), "w") as f:
    f.write(SETTINGS_PY_TEMPLATE.format(**kwargs))
  with open(os.path.join(project_name, "Lambda/project/urls.py"), "w") as f:
    f.write(URLS_PY_TEMPLATE)
  ADMIN_JSON["region"] = region
  with open(os.path.join(project_name, "admin.json"), "w") as f:
    json.dump(ADMIN_JSON, f, indent=2)







