#!/usr/bin/env bash
set -euo pipefail
# from repo roo
ansible-galaxy collection install community.docker -p ./roles >/dev/null || true
ansible-playbook -i inventory/hosts.ini playbooks/deploy_ssh_honeypot.yml -v
popd >/dev/null
