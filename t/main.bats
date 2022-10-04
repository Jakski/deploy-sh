#!/usr/bin/env bash

bats_require_minimum_version 1.5.0

q() {
	printf "%q" "$*"
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
	export TEST_INPUT_FILE="${BATS_TEST_TMPDIR}/script"
	cat > "$TEST_INPUT_FILE" <<-EOF
		DEPLOY_SSH_CONFIG="\\
		StrictHostKeyChecking no
		UserKnownHostsFile /dev/null
		LogLevel ERROR
		Port 2222
		User tests
		IdentityFile ${BATS_RUN_TMPDIR}/keys/id_rsa"

		DEPLOY_DEFAULT_HOSTS="\\
		localhost1 127.0.0.1
		localhost2 127.0.0.1
		localhost3 127.0.0.1"
	EOF
}

teardown() {
	rm -f "$TEST_INPUT_FILE"
}

function simple_command { #@test
	cat >> "$TEST_INPUT_FILE" <<-"EOF"
		run_task \
			name "Test" \
			script "echo running-on-\${DEPLOY_HOST_NAME}"
	EOF
	run -0 "$TEST_SCRIPT" -f "$TEST_INPUT_FILE"
	declare i
	for i in {1..3}; do
		declare text="running-on-localhost${i}"
		if ! echo "$output" | grep "$text" >/dev/null; then
			echo "Failed to find \"${text}\" in output"
			return 1
		fi
	done
}

function parallel_running { #@test
	cat >> "$TEST_INPUT_FILE" <<-"EOF"
		run_task \
			name "Create" \
			script "touch /tmp/host-\${DEPLOY_HOST_NAME}; sleep 0.2; ls /tmp/host-*"
		run_task \
			name "Remove" \
			script "rm /tmp/host-\${DEPLOY_HOST_NAME}"
	EOF
	run -0 "$TEST_SCRIPT" -f "$TEST_INPUT_FILE"
	[ "$(echo "$output" | grep "/tmp/host-" | wc -l)" = 9 ]
}

function upload_release { #@test
	cat >> "$TEST_INPUT_FILE" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Create" \
			script "mkdir -p /tmp/code"
		run_task \
			name "Deploy" \
			local 1 \
			function "rsync_git_repository"
		run_task \
			name "Show" \
			script "stat \"\${DEPLOY_RELEASE_DIR}/t/main.bats\""
		run_task \
			name "Remove" \
			script "rm -rf /tmp/code"
	EOF
	run -0 "$TEST_SCRIPT" -f "$TEST_INPUT_FILE" release_dir /tmp/code/1
}

function release_management { #@test
	cat >> "$TEST_INPUT_FILE" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Create" \
			script "mkdir -p /tmp/code/releases"
		run_task \
			name "Deploy" \
			local 1 \
			function "rsync_git_repository"
		run_task \
			name "Verify" \
			script "stat \"\${DEPLOY_RELEASE_DIR}/t/main.bats\" > /dev/null"
		run_task \
			name "Link" \
			script "ln -Tsf \"\${DEPLOY_RELEASE_DIR}\" /tmp/code/current"
		run_task \
			name "Remove old" \
			function "remove_old_releases"
	EOF
	declare release_num
	for release_num in {1..2}; do
		run -0 "$TEST_SCRIPT" -f "$TEST_INPUT_FILE" release_dir /tmp/code/releases/"$release_num"
	done
	cat >> "$TEST_INPUT_FILE" <<-"EOF"
		run_task \
			name "Verify current" \
			script "stat /tmp/code/current/t/main.bats > /dev/null"
		run_task \
			name "Show current" \
			script "echo -n \"Current: \" && realpath /tmp/code/current"
		run_task \
			name "Count releases" \
			script "echo -n \"Releases: \" && ls -1 /tmp/code/releases | wc -l"
		run_task \
			name "Ensure release 2 exists" \
			script "stat /tmp/code/releases/2 >/dev/null"
		run_task \
			name "Remove" \
			script "rm -rf /tmp/code"
	EOF
	run -0 "$TEST_SCRIPT" -f "$TEST_INPUT_FILE" release_dir /tmp/code/releases/3  releases_keep 2
	declare text="Current: /tmp/code/releases/3"
	if ! echo "$output" | grep "$text" >/dev/null; then
		echo "Failed to find \"${text}\" in output"
		return 1
	fi
	declare text="Releases: 2"
	if ! echo "$output" | grep "$text" >/dev/null; then
		echo "Failed to find \"${text}\" in output"
		return 1
	fi
}

function forced_fail { #@test
	cat >> "$TEST_INPUT_FILE" <<-"EOF"
		DEPLOY_DEFAULT_HOSTS="localhost1 127.0.0.1"
		run_task \
			name "Fail" \
			script "exit 1"
	EOF
	run -1 "$TEST_SCRIPT" -f "$TEST_INPUT_FILE"
}

function yaml_release_management { #@test
	cat > "$TEST_INPUT_FILE" <<EOF
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
	cat >> "$TEST_INPUT_FILE" <<"EOF"
deploy:
  - name: Create
    script: mkdir -p /tmp/code/releases
  - name: Deploy
    local: true
    function: rsync_git_repository
  - name: Verify
    script: stat "${DEPLOY_RELEASE_DIR}/t/main.bats" > /dev/null
  - name: Link
    script: ln -Tsf "${DEPLOY_RELEASE_DIR}" /tmp/code/current
  - name: Remove old
    function: remove_old_releases
EOF
	declare release_num
	for release_num in {1..2}; do
		run -0 "$TEST_SCRIPT" --format yaml -f "$TEST_INPUT_FILE" release_dir /tmp/code/releases/"$release_num"
	done
	cat >> "$TEST_INPUT_FILE" <<"EOF"
  - name: Verify current
    script: stat /tmp/code/current/t/main.bats > /dev/null
  - name: Show current
    script: |
      echo -n "Current: "
      realpath /tmp/code/current
  - name: Count releases
    script: |
      echo -n "Releases: "
      ls -1 /tmp/code/releases | wc -l
  - name: Ensure release 2 exists
    script: stat /tmp/code/releases/2 >/dev/null
  - name: Remove
    script: rm -rf /tmp/code
EOF
	run -0 "$TEST_SCRIPT" --format yaml -f "$TEST_INPUT_FILE" release_dir /tmp/code/releases/3  releases_keep 2
	declare text="Current: /tmp/code/releases/3"
	if ! echo "$output" | grep "$text" >/dev/null; then
		echo "Failed to find \"${text}\" in output"
		return 1
	fi
	declare text="Releases: 2"
	if ! echo "$output" | grep "$text" >/dev/null; then
		echo "Failed to find \"${text}\" in output"
		return 1
	fi
}

function yaml_run_once { #@test
	cat > "$TEST_INPUT_FILE" <<EOF
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
  localhost2: 127.0.0.1
deploy:
  - name: Run once
    script: 'echo "running-once-on: \${DEPLOY_HOST_NAME}"'
    run_once: true
EOF
	run -0 "$TEST_SCRIPT" --format yaml -f "$TEST_INPUT_FILE"
	[ "$(echo "$output" | grep -E '^\s*running-once-on: localhost1$' | wc -l)" = 1 ]
}
