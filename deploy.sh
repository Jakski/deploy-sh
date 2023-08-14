#!/usr/bin/env bash
################################################################################
# # deploy-sh
#
# Self-contained SSH deployment script leveraging existing system utilities.
#
# ## Usage
#
# ```./deploy.sh -f apps.yml -a frontend```
#
# ## Features
#
# - Running task in parallel using background subshells.
# - Limiting task to single host.
# - Running task locally.
# - Parsing deployment plan in YAML format.
# - Showing live output from tasks running on single target.
# - Storing deployments history in log file.
#
# YAML support requires additional Perl module. libyaml-perl on Debian.
#
# ## YAML configuration format
#
# ```yaml
# hosts:
#   <host name>: <host address>
# ssh_config: |
#   <SSH client configuration>
# applications:
#   <application name>:
#     deploy:
#       - name: <task name>
#         local: <boolean whether to run task locally or remotely via SSH>
#         run_once: <boolean whether to run task only for single host>
#         script: |
#           <task commands>
#       - name: ...
# ```
#
# ## Hook functions
#
# You can override them to change script's behaviour without modifying core functions.
#
# - `main_hook` - Runs before arguments are parsed. Allows to modify global configuration variables.
# - `parse_arguments_hook` - Runs after script arguments are parsed. Allows to override arguments.
# - `start_jobs_hook` - Runs just before background shells with task are launched. Allows to inject extra commands.
#
# ## Helper functions
#
# - `add_deployment_function FUNCTION` - Marks function for export to remote hosts via SSH. 
# - `add_deployment_variables NAME1 VALUE1 NAME2 VALUE2...` - Makes variables available in tasks with prefix `DEPLOY_`.
# - `checkout_repository URL REF` - Fetches Git repository and checks out specific ref. Remote will be recreated in case
#   destination repository already exists.
# - `link_release` - Creates `../current` link to working directory.
# - `remove_old_releases` - Remove old releases leaving `../current` link.
# - `upload_release` - Upload release to remote host using `rsync` from working directory.
# - `q STR` - Escape string for shell usage.
#
# ## Variables available during deployment
#
# - `DEPLOY_HOST_NAME` - First field of host definition.
# - `DEPLOY_HOST_ADDRESS` - Second field of host definition.
# - `DEPLOY_HOST_NUM` - Host's number. It may change between tasks.
# - `DEPLOY_RELEASE_DIR` - Target release directory relative to user's home.
#
# ## About
#
# Generating README.md:
#
# ```awk '/^#####/{flag=!flag;next}flag{sub("^..?", "");print}' deploy.sh > README.md```
################################################################################
#shellcheck disable=SC2128
# SC2128: Expanding an array without an index only gives the first element.

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob lastpipe

DEPLOY_DEFAULT_HOSTS=""
: "${DEPLOY_SSH_CONFIG:=}"

# Internally used global variables. Do not assign them here.
SCRIPT_TMP_DIR=""
ERR_MSG=""
DEPLOY_APP_NAME=""
DEPLOY_EXTRA=""
DEPLOY_LOG_FILE=""
DEPLOY_JOB_IDS=()
DEPLOY_JOB_STATUSES=()

start_jobs_hook() {
	declare extra
	if [ "$is_local" = 0 ]; then
mapfile -d "" extra <<"EOF"
mkdir -p "$DEPLOY_RELEASE_DIR"
cd "$DEPLOY_RELEASE_DIR"
EOF
		DEPLOY_TASK_EXTRA="${DEPLOY_TASK_EXTRA}${extra}"
	fi
}

parse_arguments_hook() {
	:
}

main_hook() {
	declare \
		fn \
		timestamp
	for fn in \
		q \
		exec_ssh \
		link_release \
		upload_release \
		remove_old_releases
	do
		add_deployment_function "$fn"
	done
	timestamp=$(date +%s)
	add_deployment_variables release_dir "${DEPLOY_APP_NAME:-"app"}/${timestamp}"
}

q() {
	printf '%q' "$*"
}

log() {
	declare line
	while IFS="" read -r line; do
		if [ -n "$DEPLOY_LOG_FILE" ]; then
			printf "%s\n" "$line" >> "$DEPLOY_LOG_FILE"
		fi
		printf "%s\n" "$line"
	done
}

on_error() {
	declare \
		exit_code=$? \
		cmd=$BASH_COMMAND
	if [ -n "$ERR_MSG" ]; then
		printf "%s\n" "$ERR_MSG" >&2
	else
		printf "%s\n" "Failing with exit code ${exit_code} at ${*} in command: ${cmd}" >&2
	fi
	exit "$exit_code"
}

on_exit() {
	if [ -n "$SCRIPT_TMP_DIR" ]; then
		rm -rf "$SCRIPT_TMP_DIR"
	fi
}

# Render "declare key=value" pairs of options suitable for sourcing in shell
get_opts() {
	declare \
		prefix=${GET_OPTS_PREFIX:-"OPT"} \
		name \
		value
	while [ "$#" != 0 ]; do
		name=$1 value=$2
		name="${prefix}_${name^^}"
		shift 2
		printf "%s\n" "declare $(printf '%q' "$name")=$(printf '%q' "$value")"
	done
}

deploy_from_shell() {
	declare input=$1
	#shellcheck disable=SC1090
	source "$input"
}

deploy_from_yaml() {
	: "${DEPLOY_APP_NAME:?"Application name is required"}"
	declare \
		input=$1 \
		converter \
		plan
mapfile -d "" converter <<"EOF"
use strict;
use YAML;
$YAML::XS::LoadBlessed = 0;
use warnings;

sub quote {
	my ($str) = @_;
	($str) =~ s/'/'"'"'/g;
	return "'${str}'";
}
my $input;
{
	local $/ = undef;
	$input = <STDIN>;
}
$input = Load($input);
if (exists($input->{"hosts"})) {
	my @host_names = sort(keys(%{$input->{"hosts"}}));
	my @hosts = ();
	foreach (@host_names) {
		push(@hosts, $_ . " " . $input->{"hosts"}->{$_});
	}
	print "declare DEPLOY_DEFAULT_HOSTS=" . quote(join("\n", @hosts)) . "\n";
}
print "declare DEPLOY_SSH_CONFIG=" . quote($input->{"ssh_config"} // "") . "\n";
$input = $input->{"applications"} or die ".applications must be defined.";
$input = $input->{$ARGV[0]} or die "${ARGV[0]} application is not defined.";
$input = $input->{"deploy"} 
	or die "Deployment steps(.applications.${ARGV[0]}.deploy) are not defined.";
foreach (@$input) {
	print "run_task";
	while (my ($key, $value) = each %$_) {
		print " " . quote($key) . " " . quote($value);
	}
	print "\n";
}
EOF
	plan=$(perl <(printf "%s\n" "$converter") "$DEPLOY_APP_NAME" < "$input")
	eval "$plan"
}

#shellcheck disable=SC2120
exec_ssh() {
	declare \
		host_num=${1:-"$DEPLOY_HOST_NUM"} \
		host_address=${2:-"$DEPLOY_HOST_ADDRESS"} \
		cmd=${3:-"/bin/bash -"}
	exec ssh \
		-F "${SCRIPT_TMP_DIR}/ssh_config" \
		"$host_address" \
		"$cmd"
}

exec_bash() {
	SCRIPT_TMP_DIR=$SCRIPT_TMP_DIR \
		exec /usr/bin/env bash -
}

indent() {
	declare \
		padding=$1 \
		line
	while read -r line; do
		printf "%s\n" "${padding}${line}"
	done
}

link_release() {
	: "${DEPLOY_RELEASE_DIR:?}"
	ln -Tsvf ~/"${DEPLOY_RELEASE_DIR}" ~/"${DEPLOY_RELEASE_DIR}/../current"
}

upload_release() {
	: "${DEPLOY_RELEASE_DIR:?}"
	declare \
		revision \
		revision \
		config_file
	revision=$(git rev-parse HEAD 2>/dev/null) || revision=""
	config_file=$(q "${SCRIPT_TMP_DIR}/ssh_config")
	(
		exec_ssh <<-EOF
			mkdir -p $(q "$DEPLOY_RELEASE_DIR")
			cd $(q "$DEPLOY_RELEASE_DIR")
			printf "%s\\n" $(q "$revision") > REVISION
		EOF
	)
	rsync \
		--rsh "ssh -F ${config_file}" \
		--archive \
		--exclude ".git" \
		--recursive \
		--protect-args \
		. \
		"${DEPLOY_HOST_ADDRESS}:${DEPLOY_RELEASE_DIR}"
	# rsync mirrors source directory timestamp, which makes assessing release age hard.
	(
		exec_ssh <<-EOF
			touch $(q "$DEPLOY_RELEASE_DIR")
		EOF
	)
	printf "%s\n" "Uploaded release to ~/${DEPLOY_RELEASE_DIR}"
}

checkout_repository() {
	declare \
		url=$1 \
		ref=$2 \
		remote
	if [ ! -d ".git" ]; then
		git -c init.defaultBranch=master init >/dev/null
	fi
	git clean -fxd >/dev/null
	remote=$(git remote)
	if [ -n "$remote" ]; then
		git remote remove "$remote"
	fi
	git remote add origin "$url"
	git fetch --quiet --tags origin
	git fetch --quiet origin "$ref"
	git reset --hard FETCH_HEAD
}

remove_old_releases() {
	: "${DEPLOY_RELEASE_DIR:?}"
	declare \
		releases_keep=${1:-2} \
		release_num=0 \
		releases_dir \
		release_dir \
		old_release
	# Real paths are required to avoid removing current release.
	releases_dir=$(realpath ~/"${DEPLOY_RELEASE_DIR}/..")
	release_dir=$(realpath ~/"$DEPLOY_RELEASE_DIR")
	while read -r old_release; do
		old_release="${releases_dir}/${old_release}"
		# Omit links in case `current` is used to mark latest release.
		if [ -L "$old_release" ]; then
			continue
		fi
		release_num=$((release_num + 1))
		if [ "$release_num" -le "$releases_keep" ]; then
			continue
		fi
		if [ "$old_release" = "$release_dir" ]; then
			continue
		fi
		printf "%s\n" "Removing ${old_release}"
		rm -rf "$old_release"
	done < <(ls -1t "$releases_dir")
}

start_jobs() {
	declare \
		is_local=$1 \
		script=$2 \
		hosts=$3 \
		host_num=0 \
		DEPLOY_TASK_EXTRA="" \
		exec_func="exec_ssh" \
		host_name \
		host_address
	if [ "$is_local" = 1 ]; then
		exec_func="exec_bash"
	fi
	cat > "${SCRIPT_TMP_DIR}/ssh_config" <<< "$DEPLOY_SSH_CONFIG"
	start_jobs_hook
	while read -r host_name host_address; do
		"$exec_func" "$host_num" "$host_address" >"${SCRIPT_TMP_DIR}/${host_num}.output" 2>&1 <<-EOF &
			set -euo pipefail -o errtrace
			shopt -s inherit_errexit nullglob
			DEPLOY_HOST_NAME=$(q "$host_name")
			DEPLOY_HOST_ADDRESS=$(q "$host_address")
			DEPLOY_HOST_NUM=$(q "$host_num")
			DEPLOY_APP_NAME=$(q "$DEPLOY_APP_NAME")
			${DEPLOY_EXTRA}
			${DEPLOY_TASK_EXTRA}
			${script}
		EOF
		DEPLOY_JOB_IDS+=("$!")
		host_num=$((host_num + 1))
	done <<< "$hosts"
}

read_sleep() {
	read -rt "$1" <> <(:) || :
}

tail_log() {
	declare \
		host_num=$1 \
		last=0 \
		chars \
		job_pid \
		log_fd
	exec {log_fd}<>"${SCRIPT_TMP_DIR}/${host_num}.output"
	while true; do
		if [ "$last" = 1 ]; then
			break
		fi
		last=1
		for job_pid in $(jobs -p -r); do
			if [ "$job_pid" = "${DEPLOY_JOB_IDS["$host_num"]}" ]; then
				last=0
				break
			fi
		done
		mapfile -d "" -u "$log_fd" chars
		[ -z "${chars:-}" ] || printf "%s" "$chars"
		read_sleep 0.1
	done
	if [[ ! ${chars:-} =~ $'\n'$ ]]; then
		echo
	fi
	eval "exec ${log_fd}>&-"
}

wait_for_jobs() {
	declare \
		hosts=$1 \
		host_num=0 \
		job_status \
		hosts_array
	mapfile -t hosts_array <<< "$hosts"
	while read -r host_name host_address; do
		if [ "${#hosts_array[@]}" = 1 ]; then
			printf "%s\n" "Host: ${host_name} Address: ${host_address}" | indent "  " | log
			tail_log "$host_num" "$host_name" "$host_address" \
				> >(indent "    " | flatten 1 | log)
			wait "$!"
		fi
		job_status=0
		wait "${DEPLOY_JOB_IDS["$host_num"]}" || job_status=$?
		DEPLOY_JOB_STATUSES+=("$job_status")
		host_num=$((host_num + 1))
	done <<< "$hosts"
}

flatten() {
	declare no_buffer=${1:-0}
	declare -a args=()
	if [ "$no_buffer" = 1 ]; then
		args+=("-u")
	fi
	args+=("s,\x1B\[[0-9;]*[a-zA-Z],,g")
	# Remove problematic escape codes
	# https://stackoverflow.com/a/43627833
	sed "${args[@]}"
}

report_jobs() {
	declare \
		hosts=$1 \
		errors="" \
		hosts_array \
		job_status
	mapfile -t hosts_array <<< "$hosts"
	host_num=0
	while read -r host_name host_address; do
		job_status=${DEPLOY_JOB_STATUSES["$host_num"]}
		if [ "$job_status" != 0 ]; then
			errors="Host ${host_name} failed with exit code ${job_status}"$'\n'"${errors}"
		fi
		if [ "${#hosts_array[@]}" != 1 ]; then
			printf "%s\n" "Host: ${host_name} Address: ${host_address}" | indent "  " | log
			indent "    " < "${SCRIPT_TMP_DIR}/${host_num}.output" \
				| flatten \
				| log
		fi
		host_num=$((host_num + 1))
	done <<< "$hosts"
	if [ -n "$errors" ]; then
		printf "%s\n" "-------------------------------------------------------------------------------" | log
		printf "%s\n" "$errors" | log
		ERR_MSG="Deployment failed"
		return 1
	fi
}

run_task() {
	declare \
		OPT_LOCAL=0 \
		OPT_RUN_ONCE=0 \
		OPT_HOSTS="" \
		timestamp
	eval "$(get_opts "$@")"
	if [ "$OPT_LOCAL" = "true" ]; then
		OPT_LOCAL=1
	fi
	: \
		"${OPT_NAME:?"Step's name must be provided"}" \
		"${OPT_SCRIPT:?"Step's script must be provided"}"
	if [ -z "${OPT_HOSTS:-}" ]; then
		if [ -z "${DEPLOY_DEFAULT_HOSTS:-}" ]; then
			ERR_MSG="Target hosts must be provided"
			return 1
		else
			OPT_HOSTS=$DEPLOY_DEFAULT_HOSTS
		fi
	fi
	if [ "$OPT_RUN_ONCE" = "true" ]; then
		OPT_RUN_ONCE=1
	fi
	if [ "$OPT_RUN_ONCE" = 1 ]; then
		read -r OPT_HOSTS <<< "$OPT_HOSTS"
	fi
	timestamp=$(date +"%Y-%m-%d %H:%M:%S")
	DEPLOY_JOB_IDS=()
	DEPLOY_JOB_STATUSES=()
	printf "%s\n" "${timestamp} Step: ${OPT_NAME}" | log
	# It can't be done in subshell, because Bash needs to own job IDs.
	start_jobs "$OPT_LOCAL" "$OPT_SCRIPT" "$OPT_HOSTS"
	wait_for_jobs "$OPT_HOSTS"
	report_jobs "$OPT_HOSTS"
}

get_function_body() {
	type "$1" | tail -n +4 | head -n -1
}

add_deployment_variables() {
	declare options
	options=$(GET_OPTS_PREFIX="DEPLOY" get_opts "$@")
	DEPLOY_EXTRA="${DEPLOY_EXTRA}"$'\n'"${options}"
}

add_deployment_function() {
	declare \
		fn_name=$1 \
		fn
	fn=$(type "$fn_name" | tail -n +2)
	DEPLOY_EXTRA="${DEPLOY_EXTRA}"$'\n'"${fn}"
}

lock_log_file() {
	declare \
		log_file=$1 \
		lock_fd
	if [ -n "$DEPLOY_LOG_FILE" ]; then
		return 0
	fi
	DEPLOY_LOG_FILE=$log_file
	exec {lock_fd}<>"$DEPLOY_LOG_FILE"
	ERR_MSG="Failed to acquire log file lock. Check, if concurrent deployments are running."
	flock -n "$lock_fd"
	ERR_MSG=""
}

parse_arguments() {
	declare \
		OPT_FORMAT="shell" \
		OPT_INPUT="" \
		OPT_LOGFILE=""
	while [ "$#" != 0 ]; do
		case "$1" in
		-f|--file)
			shift
			OPT_INPUT=$1
			shift
		;;
		-a|--app)
			shift
			DEPLOY_APP_NAME=$1
			shift
		;;
		--format)
			shift
			OPT_FORMAT=$1
			shift
		;;
		--logfile)
			shift
			OPT_LOGFILE=$1
			shift
		;;
		*)
			break
		;;
		esac
	done
	add_deployment_variables "$@"
	if [ -n "$OPT_INPUT" ]; then
		if [[ $OPT_INPUT == *.yml ]] || [[ $OPT_INPUT == *.yaml ]]; then
			OPT_FORMAT=yaml
		else
			OPT_FORMAT=shell
		fi
	fi
	parse_arguments_hook
	: "${OPT_INPUT:?"Input file(-f|--file) is required"}"
	if [ -n "$OPT_LOGFILE" ]; then
		lock_log_file "$OPT_LOGFILE"
	fi
	if command -v "deploy_from_${OPT_FORMAT}" >/dev/null; then
		"deploy_from_${OPT_FORMAT}" "$OPT_INPUT"
	else
		printf "%s\n" "Wrong deployment format: ${OPT_FORMAT}" >&2
		return 1
	fi
}

main() {
	trap 'on_error "${BASH_SOURCE[0]}:${LINENO}"' ERR
	trap on_exit EXIT
	SCRIPT_TMP_DIR=$(mktemp -d -t deploy-sh.XXXXXXXX)
	main_hook
	parse_arguments "$@"
}

main "$@"
