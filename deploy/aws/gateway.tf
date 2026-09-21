data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

resource "random_id" "bucket" { byte_length = 4 }

# Recordings and the release artifact both live here.
resource "aws_s3_bucket" "zanskar" {
  bucket        = "${var.name}-${random_id.bucket.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "zanskar" {
  bucket                  = aws_s3_bucket.zanskar.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "zanskar" {
  bucket = aws_s3_bucket.zanskar.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_iam_role" "gateway" {
  name = "${var.name}-gateway"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "gateway" {
  name = "zanskar-gateway"
  role = aws_iam_role.gateway.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Bucket", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], Resource = [aws_s3_bucket.zanskar.arn, "${aws_s3_bucket.zanskar.arn}/*"] },
      { Sid = "AssumeASGRole", Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.asg_access.arn },
    ]
  })
}

resource "aws_iam_instance_profile" "gateway" {
  name = "${var.name}-gateway"
  role = aws_iam_role.gateway.name
}

resource "aws_eip" "gateway" {
  domain = "vpc"
  tags   = { Name = "${var.name}-gateway" }
}

locals {
  hostname = var.hostname != "" ? var.hostname : "${replace(aws_eip.gateway.public_ip, ".", "-")}.sslip.io"
}

resource "aws_instance" "gateway" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.gateway_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.gateway.id]
  key_name               = aws_key_pair.boxes.key_name
  iam_instance_profile   = aws_iam_instance_profile.gateway.name
  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }
  root_block_device {
    volume_size = 20
    encrypted   = true
  }
  user_data = templatefile("${path.module}/userdata/gateway.sh.tftpl", {
    bucket   = aws_s3_bucket.zanskar.bucket
    region   = var.region
    hostname = local.hostname
  })
  user_data_replace_on_change = true
  tags                        = { Name = "${var.name}-gateway" }
  depends_on                  = [aws_s3_object.binary]
}

resource "aws_eip_association" "gateway" {
  instance_id   = aws_instance.gateway.id
  allocation_id = aws_eip.gateway.id
}

# The release artifact: built locally (make dist-linux), uploaded by Terraform.
resource "aws_s3_object" "binary" {
  bucket = aws_s3_bucket.zanskar.id
  key    = "release/zanskar-linux-amd64"
  source = "${path.module}/../../dist/zanskar-linux-amd64"
  etag   = filemd5("${path.module}/../../dist/zanskar-linux-amd64")
}
