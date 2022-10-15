#!/usr/bin/env bash
################################################################################
# Self-contained SSH deployment script leveraging existing system utilities.
#
# YAML related functions:
#   - deploy_from_yaml
#   - jq_add_field
#   - yaml_to_json
################################################################################
#shellcheck disable=SC2128
# SC2128: Expanding an array without an index only gives the first element.

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob

DEPLOY_DEFAULT_HOSTS=""
: "${DEPLOY_SSH_CONFIG:=}"

# Internally used global variables. Do not assign them here.
SCRIPT_TMP_DIR=""
ERR_MSG=""
DEPLOY_EXTRAS=""
DEPLOY_LOG_FILE=""

q() {
	printf '%q' "$*"
}

log() {
	declare line
	if [ -n "$DEPLOY_LOG_FILE" ]; then
		tee -a "$DEPLOY_LOG_FILE"
	else
		while read -r line; do
			echo "$line"
		done
	fi
}

on_error() {
	declare \
		exit_code=$? \
		cmd=$BASH_COMMAND
	if [ -n "$ERR_MSG" ]; then
		echo "$ERR_MSG" >&2
	else
		echo "Failing with exit code ${exit_code} at ${*} in command: ${cmd}" >&2
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
		echo "declare $(printf '%q' "$name")=$(printf '%q' "$value")"
	done
}

jq_add_field() {
	declare \
		name=$1 \
		default=${2:-}
	if [ -z "$default" ]; then
		echo -n "(if has(\"${name}\") then .${name} else error(\"field ${name} is required\") end)"
	else
		echo -n "(if has(\"${name}\") then .${name} else ${default} end)"
	fi
}

yaml_to_json() {
	declare script
	mapfile -d "" script <<-EOF
		from ruamel import yaml
		import json, sys
		json.dump(yaml.safe_load(sys.stdin), sys.stdout)
	EOF
	python3 -c "$script"
}

deploy_from_shell() {
	declare input=$1
	cat > "${SCRIPT_TMP_DIR}/ssh_config" <<<"$DEPLOY_SSH_CONFIG"
	#shellcheck disable=SC1090
	source "$input"
}

deploy_from_yaml() {
	declare \
		input=$1 \
		steps_query \
		base64_steps \
		hosts \
		ssh_config \
		step_name \
		step_script \
		step_run_once \
		targets \
		targets_array
	declare -a args=()
	input=$(yaml_to_json < "$input")
	hosts=$(jq -er '.hosts | to_entries[] | (.key|tostring) + " " + (.value|tostring)' <<< "$input")
	ssh_config=$(jq -r ".ssh_config" <<< "$input")
	if [ -n "$ssh_config" ]; then
		DEPLOY_SSH_CONFIG=$ssh_config
	fi
	cat > "${SCRIPT_TMP_DIR}/ssh_config" <<<"$DEPLOY_SSH_CONFIG"
	mapfile -d "" steps_query <<-EOF
		.deploy[]
		| [
				$(jq_add_field "name"),
				$(jq_add_field "script"),
				$(jq_add_field "run_once" "false"),
				$(jq_add_field "local" "false")
			][]
		| @base64
	EOF
	base64_steps=$(jq -r "$steps_query" <<< "$input")
	while read -r step_name; do
		step_name=$(echo "$step_name" | base64 -d)
		read -r step_script; step_script=$(echo "$step_script" | base64 -d)
		read -r step_run_once; step_run_once=$(echo "$step_run_once" | base64 -d)
		read -r step_local; step_local=$(echo "$step_local" | base64 -d)
		targets="$hosts"
		if [ "$step_run_once" = "true" ]; then
			mapfile -t targets_array <<< "$targets"
			targets=${targets_array[0]}
		fi
		args+=(
			name "$step_name"
			hosts "$targets"
			script "$step_script"
		)
		if [ "$step_local" = "true" ]; then
			args+=(local 1)
		else
			args+=(local 0)
		fi
		run_task "${args[@]}"
	done <<< "$base64_steps"
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
		echo "${padding}${line}"
	done
}

rsync_git_repository() {
	: "${DEPLOY_RELEASE_DIR:?}"
	declare \
		files \
		revision \
		config_file
	files=$(git ls-tree -r --name-only HEAD)
	revision=$(git rev-parse HEAD)
	config_file=$(printf "%s" "${SCRIPT_TMP_DIR}/ssh_config")
	rsync \
		--rsh "ssh -F ${config_file}" \
		--archive \
		--recursive \
		--protect-args \
		--files-from <(echo "$files") \
		. \
		"${DEPLOY_HOST_ADDRESS}:${DEPLOY_RELEASE_DIR}"
	exec_ssh <<-EOF
		cd $(q "$DEPLOY_RELEASE_DIR")
		echo $(q "$revision") > REVISION
	EOF
}

remove_old_releases() {
	: "${DEPLOY_RELEASE_DIR:?}"
	declare \
		release_num=0 \
		releases_dir \
		release_dir \
		old_release
	releases_dir=$(realpath "${DEPLOY_RELEASE_DIR}/..")
	release_dir=$(realpath "$DEPLOY_RELEASE_DIR")
	while read -r old_release; do
		old_release="${releases_dir}/${old_release}"
		# Omit links in case `current` is used to mark latest release.
		if [ -L "$old_release" ]; then
			continue
		fi
		release_num=$((release_num + 1))
		if [ "$release_num" -le "${DEPLOY_RELEASES_KEEP:-3}" ]; then
			continue
		fi
		if [ "$old_release" = "$release_dir" ]; then
			continue
		fi
		echo "Removing ${old_release}"
		rm -rf "$old_release"
	done < <(ls -1t "$releases_dir")
}

start_jobs() {
	declare \
		is_local=$1 \
		hosts=$2 \
		host_num=0 \
		extra_cmds="" \
		exec_func="exec_ssh" \
		host_name \
		host_address
	if [ "$is_local" = 1 ]; then
		exec_func="exec_bash"
	fi
	while read -r host_name host_address; do
		"$exec_func" "$host_num" "$host_address" >"${SCRIPT_TMP_DIR}/${host_num}.output" 2>&1 <<-EOF &
			set -euo pipefail -o errtrace
			shopt -s inherit_errexit nullglob
			${DEPLOY_EXTRAS:-}
			DEPLOY_HOST_NAME=$(q "$host_name")
			DEPLOY_HOST_ADDRESS=$(q "$host_address")
			DEPLOY_HOST_NUM=$(q "$host_num")
			${extra_cmds}
			${OPT_SCRIPT:-}
		EOF
		echo "$!"
		host_num=$((host_num + 1))
	done <<< "$hosts"
}

wait_for_jobs() {
	declare \
		hosts=$1 \
		host_jobs=$2 \
		host_num=0 \
		job_status \
		job_id
	while read -r host_name host_address; do
		job_status=0
		job_id=$(head -n 1 <<< "$host_jobs")
		host_jobs=$(tail -n +2 <<< "$host_jobs")
		wait "$job_id" || job_status=$?
		echo "$job_status" > "${SCRIPT_TMP_DIR}/${host_num}.status"
		host_num=$((host_num + 1))
	done <<< "$hosts"
}

report_jobs() {
	declare \
		hosts=$1 \
		errors="" \
		exit_code
	host_num=0
	while read -r host_name host_address; do
		echo "Host: ${host_name} Address: ${host_address}" | indent "  " | log
		exit_code=$(cat "${SCRIPT_TMP_DIR}/${host_num}.status")
		if [ "$exit_code" != 0 ]; then
			errors="Host ${host_name} failed with exit code ${exit_code}"$'\n'"${errors}"
		fi
		# Remove problematic escape codes
		# https://stackoverflow.com/a/43627833
		indent "    " < "${SCRIPT_TMP_DIR}/${host_num}.output" \
			| sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" \
			| log
		host_num=$((host_num + 1))
	done <<< "$hosts"
	if [ -n "$errors" ]; then
		echo "-------------------------------------------------------------------------------" | log
		echo "$errors" | log
		ERR_MSG="Deployment failed"
		return 1
	fi
}

run_task() {
	declare \
		OPT_LOCAL=0 \
		OPT_HOSTS="" \
		timestamp \
		host_jobs
	eval "$(get_opts "$@")"
	: "${OPT_NAME:?"Step's name must be provided"}"
	if [ -z "${OPT_HOSTS:-}" ]; then
		if [ -z "${DEPLOY_DEFAULT_HOSTS:-}" ]; then
			ERR_MSG="Target hosts must be provided"
			return 1
		else
			OPT_HOSTS=$DEPLOY_DEFAULT_HOSTS
		fi
	fi
	timestamp=$(date +"%Y-%m-%d %H:%M:%S")
	echo "${timestamp} Step: ${OPT_NAME}" | log
	# It can't be done in subshell, because Bash needs to own job IDs.
	start_jobs "$OPT_LOCAL" "$OPT_HOSTS" > "${SCRIPT_TMP_DIR}/jobs"
	mapfile -d "" host_jobs < "${SCRIPT_TMP_DIR}/jobs"
	wait_for_jobs "$OPT_HOSTS" "$host_jobs"
	report_jobs "$OPT_HOSTS"
}

get_function_body() {
	type "$1" | tail -n +4 | head -n -1
}

add_deployment_variables() {
	declare options
	options=$(GET_OPTS_PREFIX="DEPLOY" get_opts "$@")
	DEPLOY_EXTRAS="${DEPLOY_EXTRAS}"$'\n'"${options}"
}

add_deployment_function() {
	declare \
		fn_name=$1 \
		fn
	fn=$(type "$fn_name" | tail -n +2)
	DEPLOY_EXTRAS="${DEPLOY_EXTRAS}"$'\n'"${fn}"
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
		opt_format="shell" \
		opt_input=""
	while [ "$#" != 0 ]; do
		case "$1" in
		-f|--file)
			shift
			opt_input=$1
			shift
		;;
		--format)
			shift
			opt_format=$1
			shift
		;;
		--logfile)
			shift
			lock_log_file "$1"
			shift
		;;
		*)
			break
		;;
		esac
	done
	add_deployment_variables "$@"
	if command -v "deploy_from_${opt_format}" >/dev/null; then
		"deploy_from_${opt_format}" "$opt_input"
	else
		echo "Wrong deployment format: ${opt_format}" >&2
		return 1
	fi
}

main() {
	declare fn
	declare -a send_functions
	trap 'on_error "${BASH_SOURCE[0]}:${LINENO}"' ERR
	trap on_exit EXIT
	SCRIPT_TMP_DIR=$(mktemp -d -t deploy-sh.XXXXXXXX)
	send_functions=(
		q
		exec_ssh
		rsync_git_repository
		remove_old_releases
	)
	for fn in "${send_functions[@]}"; do
		add_deployment_function "$fn"
	done
	parse_arguments "$@"
}

main "$@"
