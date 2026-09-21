data "aws_availability_zones" "az" { state = "available" }

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

# Public subnet: the gateway only.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.0.0/24"
  availability_zone       = data.aws_availability_zones.az.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public" }
}

# Private subnets (two AZs for the autoscaling group): targets have no public
# IPs and no internet route. The gateway reaches them over the VPC.
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.az.names[count.index]
  tags              = { Name = "${var.name}-private-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# EC2 Instance Connect and the EC2 API are reached by the GATEWAY (which has
# internet); the private instances need nothing outbound for this test.

resource "aws_security_group" "gateway" {
  name        = "${var.name}-gateway"
  description = "Zanskar gateway: HTTPS from the admin only"
  vpc_id      = aws_vpc.main.id
  ingress {
    description = "HTTPS from admin"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  ingress {
    description = "HTTP for ACME challenge"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH bootstrap from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "targets" {
  name        = "${var.name}-targets"
  description = "Test targets: reachable only from the gateway"
  vpc_id      = aws_vpc.main.id
  dynamic "ingress" {
    for_each = { ssh = 22, rdp = 3389, winrm = 5986 }
    content {
      description     = ingress.key
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      security_groups = [aws_security_group.gateway.id]
    }
  }
  # The load balancer health check on the autoscaling group.
  ingress {
    description = "NLB health check"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
