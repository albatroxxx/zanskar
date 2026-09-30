# Optional lab on top of the test environment (-var lab=true): an Active
# Directory domain with a domain-joined Windows member and an AD-joined Linux
# member, an RDS MySQL instance and a Windows autoscaling group, for the
# identity-provider, database and autoscaling QA. Everything here is gated so
# the plain environment stays as it was.

variable "lab" { default = false }
variable "lab_windows_asg_size" { default = 1 }

locals {
  lab_domain  = "corp.zanskar.lab"
  lab_netbios = "CORP"
  lab_base_dn = "DC=corp,DC=zanskar,DC=lab"
  lab_dc_ip   = "10.42.1.53"
  lab_count   = var.lab ? 1 : 0
}

# The private subnets have no internet route; the Linux member installs SSSD
# from the distribution repositories, so the lab adds a NAT gateway.
resource "aws_eip" "nat" {
  count  = local.lab_count
  domain = "vpc"
  tags   = { Name = "${var.name}-nat" }
}

resource "aws_nat_gateway" "lab" {
  count         = local.lab_count
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public.id
  tags          = { Name = "${var.name}-nat" }
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private_lab" {
  count  = local.lab_count
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.lab[0].id
  }
  tags = { Name = "${var.name}-private-lab" }
}

resource "aws_route_table_association" "private_lab" {
  count          = var.lab ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private_lab[0].id
}

# Lab members talk to each other freely (AD needs a dozen ports both ways);
# the gateway reaches LDAPS on the controller.
resource "aws_security_group" "lab" {
  count       = local.lab_count
  name        = "${var.name}-lab"
  description = "AD lab members: open inside the VPC"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "random_password" "lab_admin" {
  count   = local.lab_count
  length  = 20
  special = false
}
resource "random_password" "lab_users" {
  for_each = var.lab ? toset(["alice", "bob", "carol", "winops", "bind"]) : toset([])
  length   = 20
  special  = false
}
resource "random_password" "rds" {
  count   = local.lab_count
  length  = 24
  special = false
}

# The controller exports its LDAPS certificate to the environment's bucket.
resource "aws_iam_role" "lab_dc" {
  count = local.lab_count
  name  = "${var.name}-lab-dc"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "lab_dc" {
  count = local.lab_count
  name  = "lab-export"
  role  = aws_iam_role.lab_dc[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.zanskar.arn}/lab/*" }]
  })
}
# Systems Manager gives the lab a way in to the Windows boxes without RDP:
# the controller needs its LDAPS certificate repaired after promotion, and the
# member is checked for its domain join the same way.
resource "aws_iam_role_policy_attachment" "lab_dc_ssm" {
  count      = local.lab_count
  role       = aws_iam_role.lab_dc[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "lab_dc" {
  count = local.lab_count
  name  = "${var.name}-lab-dc"
  role  = aws_iam_role.lab_dc[0].name
}

resource "aws_instance" "lab_dc" {
  count                  = local.lab_count
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.private[0].id
  private_ip             = local.lab_dc_ip
  vpc_security_group_ids = [aws_security_group.targets.id, aws_security_group.lab[0].id]
  key_name               = aws_key_pair.windows.key_name
  iam_instance_profile   = aws_iam_instance_profile.lab_dc[0].name
  get_password_data      = true
  metadata_options { http_tokens = "required" }
  root_block_device {
    volume_size = 40
    encrypted   = true
  }
  user_data = templatefile("${path.module}/userdata/ad-dc.ps1.tftpl", {
    domain          = local.lab_domain
    netbios         = local.lab_netbios
    base_dn         = local.lab_base_dn
    dc_ip           = local.lab_dc_ip
    bucket          = aws_s3_bucket.zanskar.bucket
    admin_password  = random_password.lab_admin[0].result
    alice_password  = random_password.lab_users["alice"].result
    bob_password    = random_password.lab_users["bob"].result
    carol_password  = random_password.lab_users["carol"].result
    winops_password = random_password.lab_users["winops"].result
    bind_password   = random_password.lab_users["bind"].result
  })
  user_data_replace_on_change = true
  tags                        = { Name = "${var.name}-lab-dc" }
}

resource "aws_instance" "lab_win" {
  count                  = local.lab_count
  ami                    = data.aws_ami.windows.id
  instance_type          = var.windows_instance_type
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.targets.id, aws_security_group.lab[0].id]
  key_name               = aws_key_pair.windows.key_name
  iam_instance_profile   = aws_iam_instance_profile.lab_dc[0].name
  get_password_data      = true
  metadata_options { http_tokens = "required" }
  root_block_device {
    volume_size = 30
    encrypted   = true
  }
  user_data = templatefile("${path.module}/userdata/ad-member.ps1.tftpl", {
    domain         = local.lab_domain
    netbios        = local.lab_netbios
    dc_ip          = local.lab_dc_ip
    admin_password = random_password.lab_admin[0].result
  })
  user_data_replace_on_change = true
  tags                        = { Name = "${var.name}-lab-win" }
  depends_on                  = [aws_instance.lab_dc]
}

resource "aws_instance" "lab_linux" {
  count                  = local.lab_count
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.linux_instance_type
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.targets.id, aws_security_group.lab[0].id]
  key_name               = aws_key_pair.boxes.key_name
  metadata_options { http_tokens = "required" }
  root_block_device { encrypted = true }
  user_data = templatefile("${path.module}/userdata/ad-linux.sh.tftpl", {
    domain         = local.lab_domain
    dc_ip          = local.lab_dc_ip
    admin_password = random_password.lab_admin[0].result
  })
  user_data_replace_on_change = true
  tags                        = { Name = "${var.name}-lab-linux" }
  depends_on                  = [aws_instance.lab_dc, aws_nat_gateway.lab]
}

# RDS MySQL, reachable from the gateway only.
resource "aws_security_group" "rds" {
  count       = local.lab_count
  name        = "${var.name}-rds"
  description = "RDS: MySQL from the gateway"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_subnet_group" "lab" {
  count      = local.lab_count
  name       = "${var.name}-lab"
  subnet_ids = aws_subnet.private[*].id
}
resource "aws_db_instance" "lab" {
  count                   = local.lab_count
  identifier              = "${var.name}-lab"
  engine                  = "mysql"
  engine_version          = "8.4"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_encrypted       = true
  db_name                 = "app"
  username                = "admin"
  password                = random_password.rds[0].result
  db_subnet_group_name    = aws_db_subnet_group.lab[0].name
  vpc_security_group_ids  = [aws_security_group.rds[0].id]
  publicly_accessible     = false
  skip_final_snapshot     = true
  deletion_protection     = false
  apply_immediately       = true
  backup_retention_period = 0
}

# A Windows autoscaling group beside the Linux one: same role, same NLB, a
# TCP/3389 target group.
resource "aws_launch_template" "win" {
  count         = local.lab_count
  name_prefix   = "${var.name}-win-"
  image_id      = data.aws_ami.windows.id
  instance_type = var.windows_instance_type
  key_name      = aws_key_pair.windows.key_name
  user_data     = base64encode(file("${path.module}/userdata/windows.ps1"))
  # The lab group lets the NLB TCP/3389 health check reach the instances; the
  # targets group only admits 22 from inside the VPC.
  vpc_security_group_ids = [aws_security_group.targets.id, aws_security_group.lab[0].id]
  metadata_options { http_tokens = "required" }
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 30
      encrypted   = true
    }
  }
  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name}-win", Role = "asg" }
  }
}
resource "aws_lb_target_group" "win" {
  count    = local.lab_count
  name     = "${var.name}-win"
  port     = 3389
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id
  health_check { protocol = "TCP" }
}
resource "aws_lb_listener" "win" {
  count             = local.lab_count
  load_balancer_arn = aws_lb.web.arn
  port              = 3389
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.win[0].arn
  }
}
resource "aws_autoscaling_group" "win" {
  count                     = local.lab_count
  name                      = "${var.name}-win"
  min_size                  = 0
  max_size                  = 2
  desired_capacity          = var.lab_windows_asg_size
  vpc_zone_identifier       = aws_subnet.private[*].id
  target_group_arns         = [aws_lb_target_group.win[0].arn]
  health_check_type         = "ELB"
  health_check_grace_period = 600
  launch_template {
    id      = aws_launch_template.win[0].id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "${var.name}-win"
    propagate_at_launch = true
  }
}

resource "local_sensitive_file" "lab_secrets" {
  count           = local.lab_count
  filename        = "${path.module}/../../data/ad-lab.txt"
  file_permission = "0600"
  content         = <<-TXT
    AD lab (${var.name}), created by terraform ${timestamp()}
    domain ${local.lab_domain} (${local.lab_netbios}), base DN ${local.lab_base_dn}
    controller ${local.lab_dc_ip}  domain admin: ${local.lab_netbios}\Administrator / ${random_password.lab_admin[0].result}
    users (OU=Zanskar): alice (zanskar-windows) / ${random_password.lab_users["alice"].result}
                        bob (zanskar-windows + zanskar-linux) / ${random_password.lab_users["bob"].result}
                        carol (no groups) / ${random_password.lab_users["carol"].result}
                        winops (service account for the vaulted domain credential) / ${random_password.lab_users["winops"].result}
                        zanskar-bind (LDAP bind, read only) / ${random_password.lab_users["bind"].result}
    windows member ${aws_instance.lab_win[0].private_ip}   linux member ${aws_instance.lab_linux[0].private_ip}
    rds ${aws_db_instance.lab[0].address}:3306  admin / ${random_password.rds[0].result}  db app
    windows asg ${aws_autoscaling_group.win[0].name}
  TXT
}

output "lab_dc_ip" { value = var.lab ? local.lab_dc_ip : null }
output "lab_windows_ip" { value = var.lab ? aws_instance.lab_win[0].private_ip : null }
output "lab_linux_ip" { value = var.lab ? aws_instance.lab_linux[0].private_ip : null }
output "lab_rds_endpoint" { value = var.lab ? aws_db_instance.lab[0].address : null }
output "lab_windows_asg" { value = var.lab ? aws_autoscaling_group.win[0].name : null }
