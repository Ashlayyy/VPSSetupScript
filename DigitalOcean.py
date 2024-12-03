import requests
import time
import paramiko
import sys

class DigitalOceanDeployer:
    def __init__(self, api_token, ssh_key_path):
        self.api_token = api_token
        self.base_url = "https://api.digitalocean.com/v2"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.ssh_key_path = ssh_key_path

    def create_droplet(self, name, region="ams3", size="s-1vcpu-1gb", image="ubuntu-20-04-x64"):
        payload = {
            "name": name,
            "region": region,
            "size": size,
            "image": image,
            "ssh_keys": [self.get_or_create_ssh_key()],
            "backups": False,
            "ipv6": True,
            "monitoring": True,
            "tags": ["auto-deploy"]
        }

        response = requests.post(
            f"{self.base_url}/droplets",
            headers=self.headers,
            json=payload
        )

        if response.status_code != 202:
            raise Exception(f"Failed to create droplet: {response.text}")

        return response.json()["droplet"]["id"]

    def get_or_create_ssh_key(self):
        # Read public key
        with open(f"{self.ssh_key_path}.pub", "r") as f:
            public_key = f.read().strip()

        # Check if key already exists
        response = requests.get(f"{self.base_url}/account/keys", headers=self.headers)
        for key in response.json()["ssh_keys"]:
            if key["public_key"] == public_key:
                return key["id"]

        # Create new key
        response = requests.post(
            f"{self.base_url}/account/keys",
            headers=self.headers,
            json={
                "name": "auto-deploy-key",
                "public_key": public_key
            }
        )

        return response.json()["ssh_key"]["id"]

    def wait_for_droplet(self, droplet_id):
        while True:
            response = requests.get(
                f"{self.base_url}/droplets/{droplet_id}",
                headers=self.headers
            )
            
            if response.json()["droplet"]["status"] == "active":
                return response.json()["droplet"]["networks"]["v4"][0]["ip_address"]
            
            time.sleep(10)

    def setup_server(self, ip_address):
        # Wait for SSH to be available
        time.sleep(30)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        private_key = paramiko.RSAKey.from_private_key_file(self.ssh_key_path)
        
        try:
            ssh.connect(ip_address, username="root", pkey=private_key)
            
            # Execute setup commands
            commands = [
                "apt-get update",
                "apt-get install git -y",
                "git clone https://github.com/Ashlayyy/VPSSetupScript.git",
                "cd VPSSetupScript",
                "chmod +x setup.sh",
                "./setup.sh --domain ashlaysteur.com --githubHook PortfolioAsh=lqPyrBk2fTpyKe6KPWlQ --githubUrl https://github.com/Ashlayyy/Portfolio-ashlay.git --githubBranch master --user ash --createUser ash --project PortfolioAsh --filename server.js --ssl --port 8000 --email ashlay.prive@gmail.com --ssh-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMc0pIS5uv/BGA7N8DBPwQaPKzOlFhtbSqRx7sytBUU0 ashla@DESKTOP-IOIIFT1' --ip 161.35.245.19 --ip2 146.190.24.169"
            ]

            for command in commands:
                print(f"Executing: {command}")
                stdin, stdout, stderr = ssh.exec_command(command)
                print(stdout.read().decode())
                print(stderr.read().decode())

        finally:
            ssh.close()

def main():
    if len(sys.argv) != 3:
        print("Usage: python deploy.py <do_api_token> <ssh_key_path>")
        sys.exit(1)

    api_token = sys.argv[1]
    ssh_key_path = sys.argv[2]

    deployer = DigitalOceanDeployer(api_token, ssh_key_path)
    
    try:
        print("Creating droplet...")
        droplet_id = deployer.create_droplet("auto-deploy-server")
        
        print("Waiting for droplet to be ready...")
        ip_address = deployer.wait_for_droplet(droplet_id)
        
        print(f"Droplet is ready at {ip_address}")
        print("Setting up server...")
        deployer.setup_server(ip_address)
        
        print("Setup complete!")
        print(f"Server IP: {ip_address}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
