#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Created: 2025-02-28 20:34:16

import sys
import os
import subprocess
import json
import importlib


def parse_args():
  import argparse
  parser = argparse.ArgumentParser(description="""\
This is a command line tool for managing hads project.
""", formatter_class = argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument("--version", action="version", version='%(prog)s 0.0.1')
  parser.add_argument("-p", "--profile", metavar="profile", help="aws profile, this takes precedence over admin file")
  parser.add_argument("-r", "--region", metavar="region", help="aws region, this takes precedence over admin file")
  parser.add_argument("-s", "--static-sync2s3", action="store_true", help="sync static files to s3")
  parser.add_argument("-b", "--build", action="store_true", help="exec sam build")
  parser.add_argument("-d", "--deploy", action="store_true", help="exec sam deploy")
  parser.add_argument("-c", "--no-confirm-changeset", action="store_true", help="add --no-confirm-changeset when exec sam deploy")
  parser.add_argument("--delete", action="store_true", help="exec sam delete")
  parser.add_argument("-i", "--init", action="store_true", help="create hads project")
  parser.add_argument("-g", "--test-get", metavar="path", help="test get method")
  parser.add_argument("-e", "--test-get-event", metavar="path", help="test get method by event file")
  parser.add_argument("--sam", nargs="*", metavar="arg", help="exec sam command")
  parser.add_argument("--aws", nargs="*", metavar="arg", help="exec aws command")
  parser.add_argument(
    "-l", "--local-server-run", metavar="profile", choices=["sam", "static", "proxy"],
    help="aws profile, this takes precedence over admin file"
  )
  parser.add_argument("file", metavar="admin-file", nargs="?", help="input file")
  options = parser.parse_args()
  if options.file is None and options.init:
    pass
    # print("Error: missing admin file")
    # sys.exit()
  else:
    if not os.path.exists(options.file):
      print(f"Error: file '{options.file}' does not exist")
      sys.exit()
  return options

def main():
  options = parse_args()
  if options.init:
    from hads.init_option import gen_templates
    gen_templates()
    sys.exit()
  if options.file is None:
    print("Error: missing admin file")
    sys.exit()
  else:
    # adminファイルを読み込む
    with open(options.file) as f:
      admin = json.load(f)
    sys.path.append(os.path.join(os.path.dirname(options.file),"Lambda"))
    from project import settings
    CWD = os.path.abspath(os.path.dirname(options.file))
    # 環境変数を設定
    env = os.environ.copy()
    if options.profile:
      profile = options.profile
      env["AWS_PROFILE"] = profile
    else:
      try:
        if admin["profile"]:
          profile = admin["profile"]
        else:
          profile = "default"
      except KeyError:
        profile = "default"
      env["AWS_PROFILE"] = profile
    if options.region:
      region = options.region
      env["AWS_DEFAULT_REGION"] = region
    else:
      try:
        if admin["region"]:
          region = admin["region"]
          env["AWS_DEFAULT_REGION"] = region
        else:
          raise Exception("region is not defined")
      except KeyError:
        raise Exception("region is not defined")
    # 各オプションの処理
    if options.local_server_run:
      if options.local_server_run == "sam":
        subprocess.run(["sam", "local", "start-api", "--port", str(admin["local_server"]["port"]["sam"]), "--profile", profile, "--region", region], env=env, cwd=CWD)
      elif options.local_server_run == "static":
        from hads.local_server import run_static_server 
        run_static_server(
          settings.STATIC_URL, 
          os.path.join(CWD, admin["static"]["local"]),
          admin["local_server"]["port"]["static"]
        )
      elif options.local_server_run == "proxy":
        from hads.local_server import run_proxy_server 
        run_proxy_server(
          settings.STATIC_URL,
          admin["local_server"]["port"]["proxy"],
          admin["local_server"]["port"]["sam"],
          admin["local_server"]["port"]["static"]
        )
      sys.exit()
    if options.test_get_event:
      with open(options.test_get_event) as f:
        event = json.load(f)
      from lambda_function import lambda_handler
      response = lambda_handler(event, None)
      print("Response:")
      print(response)
      sys.exit()
    if options.test_get is not None:
      if not options.test_get.startswith("/"):
        print("Error: path must start with '/'")
        sys.exit()
      from lambda_function import lambda_handler
      response = lambda_handler(
        {
          "path": options.test_get,
          "requestContext":{
            "httpMethod": "GET"
          }
        },
        None
      )
      print("Response:")
      print(response)
      sys.exit()
    if options.static_sync2s3:
      if admin.get("static") and admin["static"].get("local") and admin["static"].get("s3"):
        print("Exec: aws s3 sync")
        CMD_LIST = ["aws", "s3", "sync", admin["static"]["local"], admin["static"]["s3"], "--delete"]
        print("Exec: " + " ".join(CMD_LIST))
        subprocess.run(CMD_LIST, env=env, cwd=CWD)
      else:
        print("Error: static.local or static.s3 is not defined")
        sys.exit()
    if options.sam:
      print(f"Exec: sam {' '.join(options.sam)}")
      subprocess.run(["sam"] + options.sam, env=env, cwd=CWD)
    if options.aws:
      print(f"Exec: aws {' '.join(options.aws)}")
      subprocess.run(["aws"] + options.aws, env=env, cwd=CWD)
    if options.build:
      print("Exec: sam build")
      subprocess.run(["sam", "build", "--profile", profile, "--region", region], env=env, cwd=CWD)
    if options.deploy:
      if options.no_confirm_changeset:
        print("Exec: sam deploy --no-confirm-changeset")
        subprocess.run(["sam", "deploy", "--profile", profile, "--region", region, "--no-confirm-changeset"], env=env, cwd=CWD)
      else:
        print("Exec: sam deploy")
        subprocess.run(["sam", "deploy", "--profile", profile, "--region", region], env=env, cwd=CWD)
    if options.delete:
      print("Exec: sam delete")
      subprocess.run(["sam", "delete", "--profile", profile, "--region", region], env=env, cwd=CWD)

if __name__ == '__main__':
  main()
