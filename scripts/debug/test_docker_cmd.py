import docker
client = docker.from_env()
try:
    print(client.containers.run('python:3.11-slim', 'sh -c "mkdir -p /tmp/workspace && cp -R /host_workspace/. /tmp/workspace/ 2>/dev/null || true; cd /tmp/workspace && pwd"', volumes={'c:/Users/Akshat gupta/VulnGuard': {'bind': '/host_workspace', 'mode': 'ro'}}, tmpfs={'/tmp': 'size=100m,exec'}, user='nobody', remove=True).decode('utf-8'))
except Exception as e:
    print("ERROR:")
    if hasattr(e, 'stderr'):
        print(e.stderr)
    print(str(e))
