import docker
client = docker.from_env()
try:
    print(client.containers.run('python:3.11-slim', 'su -s /bin/sh nobody -c "id"', remove=True).decode('utf-8'))
except Exception as e:
    print("ERROR:")
    if hasattr(e, 'stderr'):
        print(e.stderr)
    print(str(e))
