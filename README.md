# deploy-sh

Self-contained SSH deployment script leveraging existing system utilities.

## Usage

```./deploy.sh -f apps.yml -a frontend```

## Features

- Running task in parallel using background subshells.
- Limiting task to single host.
- Running task locally.
- Parsing deployment plan in YAML format.
- Showing live output from tasks running on single target.
- Storing deployments history in log file.

YAML support requires additional Perl module. libyaml-perl on Debian.

## YAML configuration format

```yaml
hosts:
  <host name>: <host address>
ssh_config: |
  <SSH client configuration>
applications:
  <application name>:
    deploy:
      - name: <task name>
        local: <boolean whether to run task locally or remotely via SSH>
        run_once: <boolean whether to run task only for single host>
        script: |
          <task commands>
      - name: ...
```

## Hook functions

You can override them to change script's behaviour without modifying core functions.

- `main_hook` - Runs before arguments are parsed. Allows to modify global configuration variables.
- `parse_arguments_hook` - Runs after script arguments are parsed. Allows to override arguments.
- `start_jobs_hook` - Runs just before background shells with task are launched. Allows to inject extra commands.

## Helper functions

- `add_deployment_function FUNCTION` - Marks function for export to remote hosts via SSH. 
- `add_deployment_variables NAME1 VALUE1 NAME2 VALUE2...` - Makes variables available in tasks with prefix `DEPLOY_`.
- `checkout_repository URL REF` - Fetches Git repository and checks out specific ref. Remote will be recreated in case
  destination repository already exists.
- `link_release` - Creates `../current` link to working directory.
- `remove_old_releases` - Remove old releases leaving `../current` link.
- `upload_release` - Upload release to remote host using `rsync` from working directory.
- `q STR` - Escape string for shell usage.

## Variables available during deployment

- `DEPLOY_HOST_NAME` - First field of host definition.
- `DEPLOY_HOST_ADDRESS` - Second field of host definition.
- `DEPLOY_HOST_NUM` - Host's number. It may change between tasks.
- `DEPLOY_RELEASE_DIR` - Target release directory relative to user's home.

## About

Generating README.md:

```awk '/^#####/{flag=!flag;next}flag{sub("^..?", "");print}' deploy.sh > README.md```
