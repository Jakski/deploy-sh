#!/usr/bin/env bash
#shellcheck disable=SC2128
# SC2128: Expanding an array without an index only gives the first element.

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob

SCRIPT_TMP_DIR=""
ERR_MSG=""
DEPLOY_DEFAULT_HOSTS=""

q() {
	printf '%q' "$*"
}

on_error() {
	declare exit_code=$? cmd=$BASH_COMMAND
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

ensure_tmp_dir() {
	if [ -z "$SCRIPT_TMP_DIR" ]; then
		SCRIPT_TMP_DIR=$(mktemp -d -t deploy-sh.XXXXXXXX)
	fi
}

# Render "declare key=value" pairs of options suitable for sourcing in shell
get_opts() {
	declare prefix=${GET_OPTS_PREFIX:-"OPT"}
	while [ "$#" != 0 ]; do
		declare name=$1 value=$2
		name="${prefix}_${name^^}"
		shift 2
		echo "declare $(printf '%q' "$name")=$(printf '%q' "$value")"
	done
}

exec_ssh() {
	declare host_num=$1 host_address=$2 cmd=${3:-"/bin/bash -"} config=${DEPLOY_SSH_CONFIG:-""}
	ensure_tmp_dir
	cat > "${SCRIPT_TMP_DIR}/${host_num}.ssh_config" <<<"$config"
	exec ssh \
		-F "${SCRIPT_TMP_DIR}/${host_num}.ssh_config" \
		"$host_address" \
		"$cmd"
}

exec_bash() {
	DEPLOY_TMP_DIR=$SCRIPT_TMP_DIR \
	DEPLOY_SSH_CONFIG=${DEPLOY_SSH_CONFIG:-} \
		exec /usr/bin/env bash -
}

indent() {
	declare padding=$1 line
	while read -r line; do
		echo "${padding}${line}"
	done
}

rsync_git_repository() {
	: \
		"${DEPLOY_RELEASES_DIR:?}"
	declare files config=${DEPLOY_SSH_CONFIG:-}
	cat > "${DEPLOY_TMP_DIR}/${DEPLOY_HOST_NUM}.ssh_config" <<<"$config"
	files=$(git ls-files --cached --other --exclude-standard)
	declare config_file
	config_file=$(printf "%s" "${DEPLOY_TMP_DIR}/${DEPLOY_HOST_NUM}.ssh_config")
	rsync \
		--rsh "ssh -F ${config_file}" \
		--archive \
		--recursive \
		--protect-args \
		--files-from <(echo "$files") \
		. \
		"${DEPLOY_HOST_ADDRESS}:${DEPLOY_RELEASES_DIR}/${DEPLOY_TIMESTAMP}"
}

start_jobs() {
	declare hosts=$1 host_num=0 host_name host_address
	while read -r host_name host_address; do
		"$exec_func" "$host_num" "$host_address" >"${SCRIPT_TMP_DIR}/${host_num}.output" 2>&1 <<-EOF &
			set -euo pipefail -o errtrace
			shopt -s inherit_errexit nullglob
			${DEPLOY_OPTIONS:-}
			DEPLOY_TIMESTAMP=$(q "$DEPLOY_TIMESTAMP")
			DEPLOY_HOST_NAME=$(q "$host_name")
			DEPLOY_HOST_ADDRESS=$(q "$host_address")
			DEPLOY_HOST_NUM=$(q "$host_num")
			${OPT_SCRIPT:-}
		EOF
		echo "$!"
		host_num=$((host_num + 1))
	done <<< "$hosts"
}

wait_for_jobs() {
	declare hosts=$1 host_jobs=$2 host_num=0
	while read -r host_name host_address; do
		declare job_status=0 job_id
		job_id=$(head -n 1 <<< "$host_jobs")
		host_jobs=$(tail -n +2 <<< "$host_jobs")
		wait "$job_id" || job_status=$?
		echo "$job_status" > "${SCRIPT_TMP_DIR}/${host_num}.status"
		host_num=$((host_num + 1))
	done <<< "$hosts"
}

report_jobs() {
	declare hosts=$1 step_name=$2 errors=""
	echo "Step: ${step_name}"
	host_num=0
	while read -r host_name host_address; do
		declare exit_code
		echo "Host: ${host_name} Address: ${host_address}" | indent "  "
		exit_code=$(cat "${SCRIPT_TMP_DIR}/${host_num}.status")
		if [ "$exit_code" != 0 ]; then
			errors="Host ${host_name} failed with exit code ${exit_code}"$'\n'"${errors}"
		fi
		indent "    " < "${SCRIPT_TMP_DIR}/${host_num}.output"
		host_num=$((host_num + 1))
	done <<< "$hosts"
	if [ -n "$errors" ]; then
		ERR_MSG="-------------------------------------------------------------------------------"
		ERR_MSG="$ERR_MSG"$'\n'"$errors"
		return 1
	fi
}

run_task() {
	eval "$(get_opts "$@")"
	: "${OPT_NAME:?"Step's name must be provided"}"
	if [ -z "${OPT_HOSTS:-}" ]; then
		if [ -z "${DEPLOY_DEFAULT_HOSTS:-}" ]; then
			ERR_MSG="Target hosts must be provided"
			return 1
		else
			declare OPT_HOSTS=$DEPLOY_DEFAULT_HOSTS
		fi
	fi
	declare exec_func="exec_ssh"
	if [ "${OPT_LOCAL:-0}" = 1 ]; then
		exec_func="exec_bash"
	fi
	ensure_tmp_dir
	if [ -n "${OPT_FUNCTION:-}" ]; then
		declare OPT_SCRIPT
		OPT_SCRIPT=$(type "$OPT_FUNCTION" | tail -n +4 | head -n -1)
	fi
	declare host_jobs
	# It can't be done in subshell, because Bash needs to own job IDs.
	start_jobs "$OPT_HOSTS" > "${SCRIPT_TMP_DIR}/jobs"
	mapfile -d "" host_jobs < "${SCRIPT_TMP_DIR}/jobs"
	wait_for_jobs "$OPT_HOSTS" "$host_jobs"
	report_jobs "$OPT_HOSTS" "$OPT_NAME"
}

main() {
	trap 'on_error "${BASH_SOURCE[0]}:${LINENO}"' ERR
	trap on_exit EXIT
	DEPLOY_TIMESTAMP=${DEPLOY_TIMESTAMP:-"$(date +%s)"}
	declare input_script=$1
	shift
	DEPLOY_OPTIONS=$(GET_OPTS_PREFIX="DEPLOY" get_opts "$@")
	#shellcheck disable=SC1090
	source "$input_script"
}

main "$@"
