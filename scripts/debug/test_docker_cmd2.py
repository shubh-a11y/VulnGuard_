import docker
client = docker.from_env()
try:
    print(client.containers.run('python:3.11-slim', 'sh -c "cd /does_not_exist"', remove=True).decode('utf-8'))
except Exception as e:
    print("ERROR:")
    if hasattr(e, 'stderr'):
        print(e.stderr)
    print(str(e))
