#~/bin/bash


#Install snort
sudo apt update
sudo apt install -y snort

#Install falco
sudo apt install -y curl gnupg lsb-release ca-certificates
#Add falco's key and repo
sudo apt install -y curl gnupg lsb-release ca-certificates
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
gpg --dearmor | sudo tee /usr/share/keyrings/falco-archive-keyring.gpg > /dev/n>
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://dow>
sudo tee /etc/apt/sources.list.d/falcosecurity.list > /dev/null
apt-cache search falco

sudo apt install -y falco
