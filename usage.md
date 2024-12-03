#!/bin/bash
apt-get install git -y
git clone https://github.com/Ashlayyy/VPSSetupScript.git
cd VPSSetupScript
chmod +x setup.sh
./setup.sh --domain ashlaysteur.com --githubHook PortfolioAsh=lqPyrBk2fTpyKe6KPWlQ --githubUrl https://github.com/Ashlayyy/Portfolio-ashlay.git --githubBranch master --user ash --createUser ash --project PortfolioAsh --filename server.js --ssl --port 8000 --email ashlay.prive@gmail.com --ssh-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMc0pIS5uv/BGA7N8DBPwQaPKzOlFhtbSqRx7sytBUU0 ashla@DESKTOP-IOIIFT1" --ip 161.35.245.19 --ip2 146.190.24.169
