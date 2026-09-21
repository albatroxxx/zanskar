# The role Zanskar assumes for the autoscaling group: trusted by the gateway's
# instance role only when the ExternalId matches. The permissions are the
# documents the Zanskar UI renders for admins.
resource "random_id" "external" { byte_length = 16 }

locals {
  external_id = "zanskar-${random_id.external.hex}"
}

resource "aws_iam_role" "asg_access" {
  name = "${var.name}-asg-access"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.gateway.arn }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = local.external_id } }
    }]
  })
}

resource "aws_iam_role_policy" "asg_access" {
  name = "zanskar-asg-access"
  role = aws_iam_role.asg_access.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ZanskarDescribe", Effect = "Allow", Resource = "*",
      Action = ["autoscaling:DescribeAutoScalingGroups", "ec2:DescribeInstances", "ec2:GetConsoleOutput", "elasticloadbalancing:DescribeTargetHealth"] },
      { Sid      = "ZanskarInstanceConnect", Effect = "Allow", Action = "ec2-instance-connect:SendSSHPublicKey",
        Resource = "arn:aws:ec2:${var.region}:*:instance/*",
      Condition = { StringEquals = { "ec2:ResourceTag/aws:autoscaling:groupName" = "${var.name}-web" } } },
    ]
  })
}

resource "aws_launch_template" "web" {
  name_prefix            = "${var.name}-web-"
  image_id               = data.aws_ami.al2023.id
  instance_type          = var.asg_instance_type
  key_name               = aws_key_pair.boxes.key_name
  vpc_security_group_ids = [aws_security_group.targets.id]
  metadata_options { http_tokens = "required" }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs { encrypted = true }
  }
  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name}-web", Role = "asg" }
  }
}

# An internal NLB gives the group a load-balancer health verdict (ADR 0011).
resource "aws_lb" "web" {
  name               = "${var.name}-web"
  internal           = true
  load_balancer_type = "network"
  subnets            = aws_subnet.private[*].id
}

resource "aws_lb_target_group" "web" {
  name     = "${var.name}-web"
  port     = 22
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id
  health_check {
    protocol            = "TCP"
    port                = "22"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
  }
}

resource "aws_lb_listener" "web" {
  load_balancer_arn = aws_lb.web.arn
  port              = 22
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_autoscaling_group" "web" {
  name                      = "${var.name}-web"
  min_size                  = 0
  max_size                  = 4
  desired_capacity          = var.asg_size
  vpc_zone_identifier       = aws_subnet.private[*].id
  target_group_arns         = [aws_lb_target_group.web.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 120
  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "${var.name}-web"
    propagate_at_launch = true
  }
}
