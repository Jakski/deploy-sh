#!/usr/bin/env bash

bats_require_minimum_version 1.5.0

q() {
	printf "%q" "$*"
}

find_in_text() {
	declare text=$1 phrase=$2
	if ! echo "$text" | grep "$phrase" >/dev/null; then
		echo "Failed to find \"${phrase}\" in output"
		return 1
	fi
}

find_in_output() {
	find_in_text "$output" "$1"
}

setup_file() {
	mkdir "${BATS_RUN_TMPDIR}/keys"
	ssh-keygen -t rsa -N "" -C "deploy-sh-tests" -f "${BATS_RUN_TMPDIR}/keys/id_rsa"
	docker run \
		-d --name deploy-sh-tests --rm \
		-v "${BATS_RUN_TMPDIR}/keys/id_rsa.pub:/etc/authorized_keys/tests:ro" \
		-p 127.0.0.1:2222:22 \
		-e "SSH_USERS=tests:$(id -u):$(id -g):/bin/bash" \
		panubo/sshd@sha256:71dfa7c3a4df8e4d8dcb95b6eb4972370bf5eed64a3e9bb9a90bf073dd77677a
	while true; do
		local banner_length
		banner_length=$(echo "" | nc -w 3 127.0.0.1 2222 | wc -l)
		sleep 1
		[ "$banner_length" -gt 0 ] && break
	done
}

teardown_file() {
	docker rm -f deploy-sh-tests
}

setup() {
	mkdir -p "${BATS_TEST_TMPDIR}"
	export TEST_SCRIPT=$(realpath "${BATS_TEST_DIRNAME}/../deploy.sh")
	export TEST_LOG_FILE="${BATS_TEST_DIRNAME}/logfile"
	export TEST_INPUT_FILE="${BATS_TEST_TMPDIR}/script"
	export DEPLOY_SSH_CONFIG="\
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
LogLevel ERROR
Port 2222
User tests
IdentityFile ${BATS_RUN_TMPDIR}/keys/id_rsa"
	cat > "${TEST_INPUT_FILE}.sh" <<-EOF
		DEPLOY_DEFAULT_HOSTS="\\
		localhost1 127.0.0.1
		localhost2 127.0.0.1
		localhost3 127.0.0.1"
	EOF
mapfile -d "" YAML_BASE_CONFIG <<EOF
---
ssh_config: |
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
  Port 2222
  User tests
  IdentityFile ${BATS_RUN_TMPDIR}/keys/id_rsa
hosts:
  localhost1: 127.0.0.1
EOF
cat > "${TEST_INPUT_FILE}.yml" <<EOF
${YAML_BASE_CONFIG}
applications:
  app:
    deploy:
EOF
	export YAML_BASE_CONFIG
}

teardown() {
	rm -f "${TEST_INPUT_FILE}.sh" "${TEST_INPUT_FILE}.yml" "$TEST_LOG_FILE"
	ssh \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		-o LogLevel=ERROR \
		-o IdentityFile="${BATS_RUN_TMPDIR}/keys/id_rsa" \
		-p 2222 \
		tests@127.0.0.1 "rm -rf ./*"
}

function simple_command { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		run_task \
			name "Test" \
			script "echo running-on-\${DEPLOY_HOST_NAME}"
	EOF
	run -0 "$TEST_SCRIPT" --logfile "$TEST_LOG_FILE" -f "${TEST_INPUT_FILE}.sh"
	declare i
	for i in {1..3}; do
		declare phrase="running-on-localhost${i}"
		find_in_output "$phrase"
		find_in_text "$(cat "$TEST_LOG_FILE")" "$phrase"
	done
}

function tailing { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Test" \
			local 1 \
			script "echo -n test-msg-; sleep 0.1; echo suffix; echo -n no-new-line"
		run_task name "test2" local 1 script "sleep 0.1"
	EOF
	run -0 "$TEST_SCRIPT" --logfile "$TEST_LOG_FILE" -f "${TEST_INPUT_FILE}.sh"
	find_in_output "test-msg-suffix"
	find_in_text  "$(cat "$TEST_LOG_FILE")" "test-msg-suffix"
	find_in_output "no-new-line"
	find_in_text "$(cat "$TEST_LOG_FILE")" "no-new-line"
}

function added_extras() { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		extra_function() {
			echo "extra-function-launched"
		}
		add_deployment_function extra_function
		add_deployment_variables testvar testvar-value
		run_task \
			name "Run extra function" \
			script "extra_function"
		run_task \
			name "Show extra variable" \
			script "echo \"\$DEPLOY_TESTVAR\""
	EOF
	run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.sh"
	find_in_output "testvar-value"
	find_in_output "extra-function-launched"
}

function parallel_running { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		run_task \
			name "Create" \
			script "touch host-\${DEPLOY_HOST_NAME}; sleep 0.2; ls host-*"
	EOF
	run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.sh"
	[ "$(echo "$output" | grep "host-" | wc -l)" = 9 ]
}

function upload_release { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Deploy" \
			local 1 \
			script "upload_release"
		run_task \
			name "Show" \
			script "stat t/main.bats"
		run_task \
			name "Ensure missing .git directory" \
			script "! stat .git"
		run_task \
			name "Show revision" \
			script "cat REVISION"
	EOF
	declare revision=$(git rev-parse HEAD)
	run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.sh" release_dir code/1
	find_in_output "$revision"
}

function release_management { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Deploy" \
			local 1 \
			script "upload_release"
		run_task \
			name "Verify" \
			script "stat t/main.bats > /dev/null"
		run_task \
			name "Link" \
			script "link_release"
		run_task \
			name "Remove old" \
			script "remove_old_releases"
	EOF
	declare release_num
	for release_num in {1..2}; do
		run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.sh" release_dir "code/${release_num}"
	done
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		run_task \
			name "Verify current" \
			script "stat ~/code/current/t/main.bats > /dev/null"
		run_task \
			name "Show current" \
			script "echo -n \"Current: \" && basename \"\$(realpath ~/code/current)\""
		run_task \
			name "Count releases" \
			script "echo -n \"Releases: \" && ls -1 ~/code | wc -l"
		run_task \
			name "Ensure release 2 exists" \
			script "stat ~/code/2 >/dev/null"
		run_task \
			name "Remove old" \
			script "remove_old_releases"
	EOF
	run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.sh" release_dir code/3
	find_in_output "Current: 3"
	find_in_output "Releases: 3"
}

function forced_fail { #@test
	cat >> "${TEST_INPUT_FILE}.sh" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Fail" \
			script "exit 44"
	EOF
	run -1 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.sh"
	find_in_output "failed with exit code 44"
}

function yaml_release_management { #@test
cat >> "${TEST_INPUT_FILE}.yml" <<"EOF"
    - name: Deploy
      local: true
      script: upload_release
    - name: Verify
      script: stat t/main.bats > /dev/null
    - name: Link
      script: link_release
    - name: Remove old
      script: remove_old_releases
EOF
	declare release_num
	for release_num in {1..2}; do
		run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.yml" -a app release_dir code/"$release_num"
	done
	cat >> "${TEST_INPUT_FILE}.yml" <<"EOF"
    - name: Verify current
      script: stat ~/code/current/t/main.bats > /dev/null
    - name: Show current
      script: |
        echo -n "Current: "
        basename "$(realpath ~/code/current)"
    - name: Count releases
      script: |
        echo -n "Releases: "
        ls -1 ~/code/ | wc -l
    - name: Ensure release 2 exists
      script: stat ~/code/2 >/dev/null
EOF
	run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.yml" -a app release_dir code/3  releases_keep 2
	find_in_output "Current: 3"
	find_in_output "Releases: 3"
}

function yaml_run_once { #@test
cat > "${TEST_INPUT_FILE}.yml" <<EOF
${YAML_BASE_CONFIG}
  localhost2: 127.0.0.1
applications:
  app:
    deploy:
    - name: Running twice
      script: 'echo "running-twice"'
    - name: Running once
      script: 'echo "running-once"'
      run_once: true
EOF
	run -0 "$TEST_SCRIPT" -f "${TEST_INPUT_FILE}.yml" -a app
	[ "$(echo "$output" | grep -E '^\s*running-twice' | wc -l)" = 2 ]
	[ "$(echo "$output" | grep -E '^\s*running-once' | wc -l)" = 1 ]
}
