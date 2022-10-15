#!/usr/bin/env bash
################################################################################
# Self-contained SSH deployment script leveraging existing system utilities.
#
# YAML support requires additional Perl module. libyaml-perl on Debian.
# Use *_hook functions to customize script behaviour.
#
# Variables available during deployment:
#   - DEPLOY_HOST_NAME - First field of host definition.
#   - DEPLOY_HOST_ADDRESS - Second field of host definition.
#   - DEPLOY_HOST_NUM - Host's number. It may change between tasks.
#   - DEPLOY_RELEASE_DIR - Target release directory relative to user's home.
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
DEPLOY_APP_NAME=""
DEPLOY_EXTRA=""
DEPLOY_LOG_FILE=""

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
		rsync_git_repository \
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
	plan=$(perl <(echo "$converter") "$DEPLOY_APP_NAME" < "$input")
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
		echo "${padding}${line}"
	done
}

link_release() {
	: "${DEPLOY_RELEASE_DIR:?}"
	ln -Tsvf ~/"${DEPLOY_RELEASE_DIR}" ~/"${DEPLOY_RELEASE_DIR}/../current"
}

rsync_git_repository() {
	: "${DEPLOY_RELEASE_DIR:?}"
	declare \
		files \
		revision \
		config_file
	files=$(git ls-tree -r --name-only HEAD)
	revision=$(git rev-parse HEAD)
	config_file=$(q "${SCRIPT_TMP_DIR}/ssh_config")
	(
		exec_ssh <<-EOF
			mkdir -p $(q "$DEPLOY_RELEASE_DIR")
			cd $(q "$DEPLOY_RELEASE_DIR")
			echo $(q "$revision") > REVISION
		EOF
	)
	rsync \
		--rsh "ssh -F ${config_file}" \
		--archive \
		--recursive \
		--protect-args \
		--files-from <(echo "$files") \
		. \
		"${DEPLOY_HOST_ADDRESS}:${DEPLOY_RELEASE_DIR}"
}

remove_old_releases() {
	: "${DEPLOY_RELEASE_DIR:?}"
	declare \
		release_num=0 \
		releases_dir \
		release_dir \
		old_release
	releases_dir=$(realpath ~/"${DEPLOY_RELEASE_DIR}/..")
	release_dir=$(realpath ~/"$DEPLOY_RELEASE_DIR")
	while read -r old_release; do
		old_release="${releases_dir}/${old_release}"
		# Omit links in case `current` is used to mark latest release.
		if [ -L "$old_release" ]; then
			continue
		fi
		release_num=$((release_num + 1))
		if [ "$release_num" -le "${DEPLOY_RELEASES_KEEP:-2}" ]; then
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
	cat > "${SCRIPT_TMP_DIR}/ssh_config" <<<"$DEPLOY_SSH_CONFIG"
	start_jobs_hook
	while read -r host_name host_address; do
		"$exec_func" "$host_num" "$host_address" >"${SCRIPT_TMP_DIR}/${host_num}.output" 2>&1 <<-EOF &
			set -euo pipefail -o errtrace
			shopt -s inherit_errexit nullglob
			DEPLOY_HOST_NAME=$(q "$host_name")
			DEPLOY_HOST_ADDRESS=$(q "$host_address")
			DEPLOY_HOST_NUM=$(q "$host_num")
			${DEPLOY_EXTRA}
			${DEPLOY_TASK_EXTRA}
			${script}
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
		OPT_RUN_ONCE=0 \
		OPT_HOSTS="" \
		timestamp \
		host_jobs
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
	echo "${timestamp} Step: ${OPT_NAME}" | log
	# It can't be done in subshell, because Bash needs to own job IDs.
	start_jobs "$OPT_LOCAL" "$OPT_SCRIPT" "$OPT_HOSTS" > "${SCRIPT_TMP_DIR}/jobs"
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
		echo "Wrong deployment format: ${OPT_FORMAT}" >&2
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
