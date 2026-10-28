# Isolation of the Agent Container

## What is set up
- The agent runs on a Docker network marked internal. Docker gives it no route
  to the internet and no external DNS.
- The agent is on that network only. The gateway is on that network and on an
  outside network, so it is the only door.
- The agent has a read only filesystem, no Linux capabilities, no new
  privileges, runs as a normal user, and holds no secret environment variables.

## How it is checked
- Static: backend/tests/test_compose_isolation.py reads docker-compose.yml.
- Runtime: agent/check_isolation.py runs inside the agent container.
- Control: the same probes run in agent_control, which has outside access, to
  show the probes can succeed when isolation is absent.
- CI runs all three on every push.

## What this does not prove
- It does not protect against a container escape or a Docker bug.
- It checks the local Docker setup only. Cloud Run uses different network
  controls and will be tested again on Day 73 to 76.
- It checks a fixed list of probes, not every possible route.
- Day 30 adds more bypass attempts from inside the agent container.