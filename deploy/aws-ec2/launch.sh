#!/usr/bin/env bash
# Launches one EC2 host (Ubuntu 24.04, Elastic IP) that builds and runs the Docker Compose stack.
# Needs the AWS CLI signed in with EC2 access (AmazonEC2FullAccess is enough).
#
#   bash deploy/aws-ec2/launch.sh                              # live on https://vault.<ip>.sslip.io, no DNS needed
#   bash deploy/aws-ec2/launch.sh --domain vault.arevei.com    # after pointing an A record at the printed Elastic IP
#
# Options: --domain <fqdn>  --email <acme email>  --type <instance type, default t3.large>
#          --ssh-cidr <cidr allowed on port 22, default: your current IP/32>  --ref <git branch/tag>
set -euo pipefail
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1

NAME=arevei-vault
DOMAIN=""; EMAIL="admin@arevei.com"; TYPE="t3.large"; SSH_CIDR=""; REF="main"
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=$2; shift 2;;
    --email) EMAIL=$2; shift 2;;
    --type) TYPE=$2; shift 2;;
    --ssh-cidr) SSH_CIDR=$2; shift 2;;
    --ref) REF=$2; shift 2;;
    *) echo "unknown option $1" >&2; exit 1;;
  esac
done
[ -n "$SSH_CIDR" ] || SSH_CIDR="$(curl -s https://checkip.amazonaws.com)/32"

echo "== region: $(aws configure get region || echo '(from AWS_REGION)')"

echo "== Ubuntu 24.04 AMI"
AMI=$(aws ec2 describe-images --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
echo "   $AMI"

echo "== SSH key pair ($NAME.pem)"
if [ ! -f "$NAME.pem" ]; then
  if aws ec2 describe-key-pairs --key-names "$NAME" >/dev/null 2>&1; then
    echo "Key pair '$NAME' exists in AWS but $NAME.pem is not here. Restore the file or delete the key pair first." >&2
    exit 1
  fi
  aws ec2 create-key-pair --key-name "$NAME" --key-type ed25519 --query KeyMaterial --output text > "$NAME.pem"
  chmod 600 "$NAME.pem"
fi

echo "== default VPC + subnet"
VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SUBNET=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC" "Name=default-for-az,Values=true" --query 'Subnets[0].SubnetId' --output text)
echo "   $VPC / $SUBNET"

echo "== security group"
SG=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$NAME-edge" "Name=vpc-id,Values=$VPC" --query 'SecurityGroups[0].GroupId' --output text)
if [ "$SG" = "None" ] || [ -z "$SG" ]; then
  SG=$(aws ec2 create-security-group --group-name "$NAME-edge" --description "Arevei Vault edge: 80/443 public, 22 restricted" --vpc-id "$VPC" --query GroupId --output text)
fi
for rule in "tcp,80,0.0.0.0/0" "tcp,443,0.0.0.0/0" "udp,443,0.0.0.0/0" "tcp,22,$SSH_CIDR"; do
  IFS=, read -r proto port cidr <<< "$rule"
  aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol "$proto" --port "$port" --cidr "$cidr" >/dev/null 2>&1 || true
done
echo "   $SG (ssh from $SSH_CIDR)"

echo "== Elastic IP"
read -r ALLOC IP < <(aws ec2 allocate-address --domain vpc \
  --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=$NAME}]" \
  --query '[AllocationId,PublicIp]' --output text)
echo "   $IP"

echo "== user data"
{
  echo '#!/usr/bin/env bash'
  echo "export VAULT_DOMAIN='$DOMAIN' ACME_EMAIL='$EMAIL' PUBLIC_IP='$IP' REPO_REF='$REF'"
  tail -n +2 bootstrap.sh
} > user-data.generated.sh

echo "== launching $TYPE"
INSTANCE=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --key-name "$NAME" \
  --subnet-id "$SUBNET" --security-group-ids "$SG" --associate-public-ip-address \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=40,VolumeType=gp3,DeleteOnTermination=true}' \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --user-data file://user-data.generated.sh \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "   $INSTANCE"
aws ec2 wait instance-running --instance-ids "$INSTANCE"
aws ec2 associate-address --instance-id "$INSTANCE" --allocation-id "$ALLOC" >/dev/null
rm -f user-data.generated.sh

[ -n "$DOMAIN" ] || DOMAIN="vault.${IP//./-}.sslip.io"
cat <<MSG

Instance $INSTANCE is up at $IP. The first build takes about 15-25 minutes.

  Vault URL:    https://$DOMAIN
  SSH:          ssh -i deploy/aws-ec2/$NAME.pem ubuntu@$IP
  Build log:    ssh -i deploy/aws-ec2/$NAME.pem ubuntu@$IP 'sudo tail -f /var/log/arevei-bootstrap.log'
  Secrets:      /opt/arevei-vault/deploy/.env   (back up SERVER_SECRET_KEY offline)
  Backup key:   /root/arevei-vault-age-key.txt  (move it OFF the host, keep offline)

Sign up as soon as the site answers: the first account becomes the organization Owner.
MSG
