import unittest

from src.guardrails import validate_compose


class GuardrailsTests(unittest.TestCase):
    def test_guardrails_pass_with_hardened_service(self):
        compose = {
            "services": {
                "agent": {
                    "read_only": True,
                    "cap_drop": ["ALL"],
                    "security_opt": [
                        "no-new-privileges:true",
                        "seccomp=./profiles/seccomp-agent.json",
                        "apparmor=docker-agent-default",
                    ],
                    "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m"],
                    "pids_limit": 128,
                    "mem_limit": "512m",
                    "environment": {"OPENAI_API_KEY_FILE": "/run/secrets/api_token"},
                    "secrets": ["api_token"],
                    "networks": ["sandbox"],
                }
            },
            "networks": {"sandbox": {"internal": True}},
            "secrets": {"api_token": {"file": "./secrets/api_token.txt"}},
        }

        self.assertEqual(validate_compose(compose), [])

    def test_guardrails_fail_on_inline_secret_and_missing_isolation(self):
        compose = {
            "services": {
                "agent": {
                    "read_only": False,
                    "cap_drop": [],
                    "security_opt": [],
                    "tmpfs": [],
                    "environment": {"OPENAI_API_KEY": "raw-secret"},
                    "secrets": [],
                    "networks": ["sandbox"],
                }
            },
            "networks": {"sandbox": {"internal": False}},
        }

        violations = validate_compose(compose)
        self.assertTrue(any("read_only" in violation for violation in violations))
        self.assertTrue(any("cap_drop must include ALL" in violation for violation in violations))
        self.assertTrue(any("inline secret" in violation for violation in violations))
        self.assertTrue(any("must be internal" in violation for violation in violations))
