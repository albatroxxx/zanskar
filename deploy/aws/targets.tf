data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

resource "aws_instance" "linux" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.linux_instance_type
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.targets.id]
  key_name               = aws_key_pair.boxes.key_name
  metadata_options { http_tokens = "required" }
  root_block_device { encrypted = true }
  tags = { Name = "${var.name}-linux", Role = "target" }
}

# Windows: user-data enables the WinRM HTTPS listener with a self-signed
# certificate (which Zanskar's probe pins) and opens the firewall for it.
resource "aws_instance" "windows" {
  ami                    = data.aws_ami.windows.id
  instance_type          = var.windows_instance_type
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.targets.id]
  key_name               = aws_key_pair.windows.key_name
  get_password_data      = true
  metadata_options { http_tokens = "required" }
  root_block_device {
    volume_size = 30
    encrypted   = true
  }
  user_data = file("${path.module}/userdata/windows.ps1")
  tags      = { Name = "${var.name}-windows", Role = "target" }
}
